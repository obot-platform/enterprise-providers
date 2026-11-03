package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenWaiterCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		once.Do(func() { close(started) })
		<-release
		if _, err := w.Write([]byte(`{"access_token":"shared","expires_in":300,"token_type":"Bearer"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	c := New(Endpoints{TokenURL: upstream.URL}, "id", "secret", upstream.Client())
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { _, err := c.accessToken(ctx); first <- err }()
	<-started
	second := make(chan error, 1)
	go func() {
		token, err := c.accessToken(t.Context())
		if err == nil && token != "shared" {
			t.Error("wrong token")
		}
		second <- err
	}()
	cancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("token waiter blocked behind network request")
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("refresh was not shared")
	}
}

func TestTokenFailureCooldown(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()
	c := New(Endpoints{TokenURL: upstream.URL}, "id", "secret", upstream.Client())
	for range 3 {
		if _, err := c.accessToken(t.Context()); err == nil {
			t.Fatal("accepted unavailable token endpoint")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("failed token refresh was not rate limited")
	}
}
