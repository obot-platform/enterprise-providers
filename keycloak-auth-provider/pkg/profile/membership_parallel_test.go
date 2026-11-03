package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMembershipParallelFailureCancelsWithoutPartialAnswer(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			completed := make(chan struct{})
			waiting := make(chan struct{})
			canceled := make(chan struct{})
			var observedCancellation sync.Once
			var observedWaiting sync.Once
			c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/person":
					if _, err := w.Write([]byte(`{"id":"person","enabled":true}`)); err != nil {
						t.Error(err)
					}
				case "/users/person/groups":
					if _, err := w.Write([]byte(`[{"id":"bad"},{"id":"good"},{"id":"waiting-1"},{"id":"waiting-2"}]`)); err != nil {
						t.Error(err)
					}
				case "/groups/bad":
					select {
					case <-completed:
						select {
						case <-waiting:
							w.WriteHeader(status)
						case <-r.Context().Done():
						}
					case <-r.Context().Done():
					}
				case "/groups/good":
					if err := json.NewEncoder(w).Encode(group{ID: "good", Name: "Good", Path: "/Good"}); err != nil {
						t.Error(err)
					}
					close(completed)
				default:
					observedWaiting.Do(func() { close(waiting) })
					<-r.Context().Done()
					observedCancellation.Do(func() { close(canceled) })
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			infos, err := FetchUserGroupInfos(ctx, c, "person")
			if err == nil || infos != nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("partial result %v, error %v", infos, err)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("failed detail did not cancel in-flight lookups")
			}
		})
	}
}

func TestMembershipParallelReadsHonorCallerCancellation(t *testing.T) {
	started := make(chan struct{})
	var observedStart sync.Once
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/person":
			if _, err := w.Write([]byte(`{"id":"person","enabled":true}`)); err != nil {
				t.Error(err)
			}
		case "/users/person/groups":
			if _, err := w.Write([]byte(`[{"id":"one"},{"id":"two"}]`)); err != nil {
				t.Error(err)
			}
		default:
			observedStart.Do(func() { close(started) })
			<-r.Context().Done()
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		infos, err := FetchUserGroupInfos(ctx, c, "person")
		if infos != nil {
			t.Error("canceled membership read returned a partial answer")
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("detail reads did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("membership read ignored caller cancellation")
	}
}

func TestMembershipDepthChecksChainsWhoseAncestorsAreAlsoDirect(t *testing.T) {
	groups := make([]group, maxDepth+1)
	for i := range groups {
		id := strings.Repeat("a", i+1)
		groups[i] = group{
			ID:   id,
			Name: "a",
			Path: strings.Repeat("/a", i+1),
		}
		if i > 0 {
			groups[i].ParentID = groups[i-1].ID
		}
	}
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var response any
		switch r.URL.Path {
		case "/users/person":
			response = map[string]any{"id": "person", "enabled": true}
		case "/users/person/groups":
			response = groups
		default:
			id := strings.TrimPrefix(r.URL.Path, "/groups/")
			response = groups[len(id)-1]
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	})
	infos, err := FetchUserGroupInfos(t.Context(), c, "person")
	if infos != nil || err == nil || !strings.Contains(err.Error(), "safety bounds") {
		t.Fatalf("over-depth direct ancestry returned %v, error %v", infos, err)
	}
}

func TestGroupResolutionFailureCancelsOtherReads(t *testing.T) {
	waiting, canceled := make(chan struct{}), make(chan struct{})
	var started, stopped sync.Once
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/groups/bad" {
			select {
			case <-waiting:
				w.WriteHeader(http.StatusForbidden)
			case <-r.Context().Done():
			}
		} else {
			started.Do(func() { close(waiting) })
			<-r.Context().Done()
			stopped.Do(func() { close(canceled) })
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	infos, err := FetchGroupsByIDs(ctx, c, []string{"bad", "waiting"})
	if infos != nil || err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("partial answer %v error %v", infos, err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("other group reads were not canceled")
	}
}

func TestTopLevelMembershipsDoNotFetchGroupDetails(t *testing.T) {
	groups := make([]group, 40)
	for i := range groups {
		name := fmt.Sprintf("Team %02d / East", i)
		groups[i] = group{
			ID:   fmt.Sprintf("id-%02d", i),
			Name: name,
			Path: "/" + name,
		}
	}
	var calls atomic.Int32
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var result any
		switch r.URL.Path {
		case "/users/person":
			result = map[string]any{"id": "person", "enabled": true}
		case "/users/person/groups":
			result = groups
		default:
			t.Errorf("unnecessary group detail request: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(result); err != nil {
			t.Error(err)
		}
	})
	infos, err := FetchUserGroupInfos(t.Context(), c, "person")
	if err != nil || len(infos) != len(groups) || calls.Load() != 2 {
		t.Fatalf("groups=%d calls=%d error=%v", len(infos), calls.Load(), err)
	}
}
