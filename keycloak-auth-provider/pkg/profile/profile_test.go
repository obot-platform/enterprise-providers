package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obot-platform/enterprise-providers/keycloak-auth-provider/pkg/client"
)

func directoryFixture(t *testing.T, handler http.HandlerFunc) *client.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/token" {
			if _, err := w.Write([]byte(`{"access_token":"directory-token","expires_in":300,"token_type":"Bearer"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer directory-token" {
			t.Error("missing directory token")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return client.New(client.Endpoints{TokenURL: server.URL + "/token", AdminURL: server.URL}, "directory", "secret", server.Client())
}

func TestMembershipAncestorsMemoAndOpaqueID(t *testing.T) {
	var rootReads atomic.Int32
	nativeUser := "f:external-provider:user/opaque"
	groups := map[string]group{
		"root":     {ID: "root", Name: "Engineering", Path: "/Engineering"},
		"platform": {ID: "platform", Path: "/Engineering/Platform", ParentID: "root"},
		"runtime":  {ID: "runtime", Path: "/Engineering/Platform/Runtime", ParentID: "platform"},
		"security": {ID: "security", Path: "/Engineering/Security", ParentID: "root"},
	}
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/" + nativeUser:
			if err := json.NewEncoder(w).Encode(map[string]any{"id": nativeUser, "enabled": true}); err != nil {
				t.Error(err)
			}
		case "/users/" + nativeUser + "/groups":
			if r.URL.Query().Get("max") != "100001" {
				t.Error("unbounded membership page")
			}
			if err := json.NewEncoder(w).Encode([]group{groups["runtime"], groups["security"]}); err != nil {
				t.Error(err)
			}
		default:
			id := strings.TrimPrefix(r.URL.Path, "/groups/")
			if id == "root" {
				rootReads.Add(1)
			}
			g, ok := groups[id]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if err := json.NewEncoder(w).Encode(g); err != nil {
				t.Error(err)
			}
		}
	})
	infos, err := FetchUserGroupInfos(context.Background(), c, nativeUser)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 4 || rootReads.Load() != 1 {
		t.Fatalf("groups %v root reads %d", infos, rootReads.Load())
	}
	for _, info := range infos {
		if !strings.HasPrefix(info.ID, "keycloak/") {
			t.Fatalf("ID %q", info.ID)
		}
	}
}

func TestMembershipParallelLookupsFitAuthenticationDeadline(t *testing.T) {
	const directCount = 120
	var active, peak, rootReads atomic.Int32
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/person":
			if _, err := w.Write([]byte(`{"id":"person","enabled":true}`)); err != nil {
				t.Error(err)
			}
		case "/users/person/groups":
			groups := make([]group, directCount)
			for i := range groups {
				groups[i] = group{
					ID:   "team-" + strconv.Itoa(i),
					Path: "/Engineering/Team-" + strconv.Itoa(i),
				}
			}
			if err := json.NewEncoder(w).Encode(groups); err != nil {
				t.Error(err)
			}
		default:
			current := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); current > old; old = peak.Load() {
				if peak.CompareAndSwap(old, current) {
					break
				}
			}
			select {
			case <-time.After(100 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			id := strings.TrimPrefix(r.URL.Path, "/groups/")
			g := group{
				ID:       id,
				Path:     "/Engineering/Team-" + strings.TrimPrefix(id, "team-"),
				ParentID: "root",
			}
			if id == "root" {
				rootReads.Add(1)
				g.Name = "Engineering"
				g.Path = "/Engineering"
				g.ParentID = ""
			}
			if err := json.NewEncoder(w).Encode(g); err != nil && r.Context().Err() == nil {
				t.Error(err)
			}
		}
	})
	// Match Obot's existing caller deadline, rather than the provider's longer limit.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	infos, err := FetchUserGroupInfos(ctx, c, "person")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != directCount+1 || rootReads.Load() != 1 {
		t.Fatalf("membership count %d, shared ancestor reads %d", len(infos), rootReads.Load())
	}
	if peak.Load() <= 1 || peak.Load() > 8 {
		t.Fatalf("concurrent detail requests %d; want between 2 and 8", peak.Load())
	}
}

func TestMembershipCompleteEqualLeafNamesAndNoPartialResult(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			var reads atomic.Int32
			c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/users/person" {
					if _, err := w.Write([]byte(`{"id":"person","enabled":true}`)); err != nil {
						t.Error(err)
					}
					return
				}
				if r.URL.Path == "/users/person/groups" {
					reads.Add(1)
					if r.URL.Query().Get("first") != "0" || r.URL.Query().Get("max") != "100001" {
						t.Error("unsafe membership offset paging")
					}
					if fail {
						w.WriteHeader(503)
						return
					}
					result := make([]group, 151)
					for i := range result {
						id := strconv.Itoa(i)
						result[i] = group{ID: id, Name: "Shared", Path: "/Department" + id + "/Shared", ParentID: "parent-" + id}
					}
					if err := json.NewEncoder(w).Encode(result); err != nil {
						t.Error(err)
					}
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/groups/")
				name := "Department" + strings.TrimPrefix(id, "parent-")
				if err := json.NewEncoder(w).Encode(group{ID: id, Name: name, Path: "/" + name}); err != nil {
					t.Error(err)
				}
			})
			infos, err := FetchUserGroupInfos(t.Context(), c, "person")
			if reads.Load() != 1 {
				t.Fatalf("membership reads %d", reads.Load())
			}
			if fail {
				if err == nil || infos != nil {
					t.Fatalf("partial result %v error %v", infos, err)
				}
			} else if err != nil || len(infos) != 302 {
				t.Fatalf("groups %d error %v", len(infos), err)
			}
		})
	}
}

func TestMembershipRejectsDuplicateAndOversizedDirectGroups(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(fmt.Sprint(duplicate), func(t *testing.T) {
			c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/users/person" {
					if _, err := w.Write([]byte(`{"id":"person","enabled":true}`)); err != nil {
						t.Error(err)
					}
					return
				}
				if r.URL.Path == "/users/person/groups" {
					n := maxGroups + 1
					if duplicate {
						n = 2
					}
					groups := make([]group, n)
					for i := range groups {
						id := strconv.Itoa(i)
						if duplicate {
							id = "same"
						}
						groups[i] = group{ID: id, Path: "/Group"}
					}
					if err := json.NewEncoder(w).Encode(groups); err != nil {
						t.Error(err)
					}
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/groups/")
				if err := json.NewEncoder(w).Encode(group{ID: id, Path: "/Group"}); err != nil {
					t.Error(err)
				}
			})
			infos, err := FetchUserGroupInfos(t.Context(), c, "person")
			if err == nil || infos != nil {
				t.Fatalf("partial answer %v error %v", infos, err)
			}
		})
	}
}

func TestUnavailableUserAndBrokenAncestry(t *testing.T) {
	cases := []struct {
		name         string
		userStatus   int
		enabled      bool
		parentStatus int
		cycle        bool
		unavailable  bool
	}{
		{
			name:        "missing user",
			userStatus:  404,
			unavailable: true,
		},
		{
			name:        "disabled user",
			userStatus:  200,
			enabled:     false,
			unavailable: true,
		},
		{
			name:       "user forbidden",
			userStatus: 403,
		},
		{
			name:         "missing ancestor",
			userStatus:   200,
			enabled:      true,
			parentStatus: 404,
		},
		{
			name:         "forbidden ancestor",
			userStatus:   200,
			enabled:      true,
			parentStatus: 403,
		},
		{
			name:         "ancestry cycle",
			userStatus:   200,
			enabled:      true,
			parentStatus: 200,
			cycle:        true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/users/p":
					if tc.userStatus != 200 {
						w.WriteHeader(tc.userStatus)
						return
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"id": "p", "enabled": tc.enabled}); err != nil {
						t.Error(err)
					}
				case "/users/p/groups":
					if _, err := w.Write([]byte(`[{"id":"child","path":"/Parent/Child","parentId":"parent"}]`)); err != nil {
						t.Error(err)
					}
				case "/groups/child":
					if _, err := w.Write([]byte(`{"id":"child","path":"/Parent/Child","parentId":"parent"}`)); err != nil {
						t.Error(err)
					}
				case "/groups/parent":
					if tc.parentStatus != 200 {
						w.WriteHeader(tc.parentStatus)
						return
					}
					parent := ""
					if tc.cycle {
						parent = "child"
					}
					if err := json.NewEncoder(w).Encode(group{ID: "parent", Name: "Parent", Path: "/Parent", ParentID: parent}); err != nil {
						t.Error(err)
					}
				default:
					t.Errorf("unexpected %s", r.URL.Path)
					w.WriteHeader(500)
				}
			})
			infos, err := FetchUserGroupInfos(context.Background(), c, "p")
			if err == nil || infos != nil {
				t.Fatalf("partial result %v error %v", infos, err)
			}
			var unavailable *UserUnavailableError
			if errors.As(err, &unavailable) != tc.unavailable {
				t.Fatalf("error type %T wanted unavailable=%v", err, tc.unavailable)
			}
		})
	}
}

func TestGroupResolutionOmits404ButSurfacesPartialFailure(t *testing.T) {
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/groups/ok":
			if _, err := w.Write([]byte(`{"id":"ok","path":"/Parent/Shared"}`)); err != nil {
				t.Error(err)
			}
		case "/groups/missing":
			w.WriteHeader(404)
		default:
			w.WriteHeader(403)
		}
	})
	infos, err := FetchGroupsByIDs(context.Background(), c, []string{"ok", "missing", "ok", "", ".", ".."})
	if err != nil || len(infos) != 1 || infos[0].ID != "keycloak/ok" {
		t.Fatalf("infos %v err %v", infos, err)
	}
	infos, err = FetchGroupsByIDs(context.Background(), c, []string{"ok", ".", "forbidden", ".."})
	if err == nil || infos != nil {
		t.Fatalf("returned partial result %v err %v", infos, err)
	}
}

func TestUserInfoKeepsNativeSubjectAndProfileRegardlessOfEmailPolicy(t *testing.T) {
	cases := []struct {
		name      string
		verified  any
		email     string
		sub       string
		wantError bool
	}{
		{
			name:     "verified email",
			verified: true,
			email:    "a@example.com",
			sub:      "f:storage:opaque-id",
		},
		{
			name:     "unverified email",
			verified: false,
			email:    "a@example.com",
			sub:      "f:storage:opaque-id",
		},
		{
			name:  "verification omitted",
			email: "a@example.com",
			sub:   "f:storage:opaque-id",
		},
		{
			name: "email omitted from profile",
			sub:  "f:storage:opaque-id",
		},
		{
			name:      "missing native subject",
			verified:  true,
			email:     "a@example.com",
			wantError: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer user-token" {
					t.Error("wrong token")
				}
				claims := map[string]any{"sub": tc.sub, "email": tc.email, "given_name": "A", "family_name": "Person", "picture": "https://example.com/avatar.png"}
				if tc.verified != nil {
					claims["email_verified"] = tc.verified
				}
				if err := json.NewEncoder(w).Encode(claims); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			info, err := GetUserInfo(context.Background(), "user-token", server.URL)
			if tc.wantError {
				if err == nil || info != nil {
					t.Fatal("accepted missing native subject")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.ID != tc.sub || info.Name != "A Person" || info.IconURL != "https://example.com/avatar.png" {
				t.Fatalf("userinfo %+v", info)
			}
		})
	}
}

func TestUnsafeNativeIDsNeverReachDirectory(t *testing.T) {
	c := directoryFixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unsafe ID reached directory") })
	for _, id := range []string{".", ".."} {
		if _, err := FetchUserGroupInfos(t.Context(), c, id); err == nil {
			t.Fatal("unsafe user ID accepted")
		}
		if infos, err := FetchGroupsByIDs(t.Context(), c, []string{id}); err != nil || len(infos) != 0 {
			t.Fatalf("invalid administrative group ID was not omitted: %v, %v", infos, err)
		}
	}
}

func TestProfileAcceptsOnlyHTTPSAvatars(t *testing.T) {
	for _, picture := range []string{"https://images.example/avatar.svg", "http://images.example/avatar.svg", "javascript:alert(1)", "data:image/svg+xml,test", "//images.example/avatar.svg", "https://user:password@images.example/avatar.svg", "https:///avatar"} {
		t.Run(picture, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if err := json.NewEncoder(w).Encode(map[string]string{"sub": "opaque-id", "name": "Example Person", "picture": picture}); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()
			info, err := GetUserInfo(t.Context(), "test-token", upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			expected := ""
			if picture == "https://images.example/avatar.svg" {
				expected = picture
			}
			if info.IconURL != expected || info.Name != "Example Person" {
				t.Fatalf("profile %v", info)
			}
		})
	}
}

func TestMembershipReusesBriefParentLinksAndReadsUserInParallel(t *testing.T) {
	userStarted := make(chan struct{})
	c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/users/person":
			close(userStarted)
			body = `{"id":"person","enabled":true}`
		case "/users/person/groups":
			select {
			case <-userStarted:
			case <-time.After(time.Second):
				t.Error("user status read did not start in parallel")
			}
			body = `[{"id":"child","parentId":"parent","path":"/Parent/Child"}]`
		case "/groups/parent":
			body = `{"id":"parent","name":"Parent","path":"/Parent"}`
		default:
			t.Errorf("unnecessary detail read %s", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	})
	infos, err := FetchUserGroupInfos(t.Context(), c, "person")
	if err != nil || len(infos) != 2 {
		t.Fatalf("memberships %v error %v", infos, err)
	}
}

func TestMembershipRequiresConfirmedRootForEveryAncestor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		brief   group
		details []group
		want    int
	}{
		{
			name: "direct detail still lacks parent",
			brief: group{
				ID:   "team",
				Name: "Team",
				Path: "/Engineering/Team",
			},
			details: []group{
				{
					ID:   "team",
					Name: "Team",
					Path: "/Engineering/Team",
				},
			},
		},
		{
			name: "ancestor detail lacks parent",
			brief: group{
				ID:       "team",
				Name:     "Team",
				Path:     "/Engineering/Platform/Team",
				ParentID: "platform",
			},
			details: []group{
				{
					ID:   "platform",
					Name: "Platform",
					Path: "/Engineering/Platform",
				},
			},
		},
		{
			name: "parentless root detail lacks name",
			brief: group{
				ID:   "root",
				Path: "/Engineering",
			},
			details: []group{
				{
					ID:   "root",
					Path: "/Engineering",
				},
			},
		},
		{
			name: "detail confirms root",
			brief: group{
				ID:   "root",
				Path: "/Engineering",
			},
			details: []group{
				{
					ID:   "root",
					Name: "Engineering",
					Path: "/Engineering",
				},
			},
			want: 1,
		},
		{
			name: "root name contains literal slash",
			brief: group{
				ID:   "root",
				Path: "/Engineering/Platform",
			},
			details: []group{
				{
					ID:   "root",
					Name: "Engineering/Platform",
					Path: "/Engineering/Platform",
				},
			},
			want: 1,
		},
		{
			name: "ancestor is a confirmed root",
			brief: group{
				ID:       "team",
				Name:     "Team",
				Path:     "/Engineering/Team",
				ParentID: "root",
			},
			details: []group{
				{
					ID:   "root",
					Name: "Engineering",
					Path: "/Engineering",
				},
			},
			want: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var detailReads atomic.Int32
			c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
				var result any
				switch r.URL.Path {
				case "/users/person":
					result = map[string]any{"id": "person", "enabled": true}
				case "/users/person/groups":
					result = []group{tc.brief}
				default:
					detailReads.Add(1)
					for _, g := range tc.details {
						if r.URL.Path == "/groups/"+g.ID {
							result = g
							break
						}
					}
					if result == nil {
						t.Errorf("unexpected group detail request %s", r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
						return
					}
				}
				if err := json.NewEncoder(w).Encode(result); err != nil {
					t.Error(err)
				}
			})
			infos, err := FetchUserGroupInfos(t.Context(), c, "person")
			if tc.want == 0 {
				if err == nil || infos != nil || !strings.Contains(err.Error(), "not a confirmed root") {
					t.Fatalf("incomplete ancestry returned %v, error %v", infos, err)
				}
			} else if err != nil || len(infos) != tc.want {
				t.Fatalf("memberships %v, error %v; want %d", infos, err, tc.want)
			}
			if detailReads.Load() != 1 {
				t.Fatalf("detail reads %d, want one full detail validation", detailReads.Load())
			}
		})
	}
}

func TestMembershipRootWithSlashes(t *testing.T) {
	for _, rootPath := range []string{"/Engineering/Platform/Ops", "/Engineering~/Platform~/Ops"} {
		for _, source := range []string{"brief", "detail", "ancestor"} {
			t.Run(rootPath+"/"+source, func(t *testing.T) {
				root := group{ID: "root", Name: "Engineering/Platform/Ops", Path: rootPath}
				brief := root
				wantCount, wantReads := 1, int32(0)
				switch source {
				case "detail":
					brief.Name = ""
					wantReads = 1
				case "ancestor":
					brief = group{ID: "child", Name: "Team", Path: rootPath + "/Team", ParentID: root.ID}
					wantCount, wantReads = 2, 1
				}
				var detailReads atomic.Int32
				c := directoryFixture(t, func(w http.ResponseWriter, r *http.Request) {
					var result any
					switch r.URL.Path {
					case "/users/person":
						result = map[string]any{"id": "person", "enabled": true}
					case "/users/person/groups":
						result = []group{brief}
					case "/groups/root":
						detailReads.Add(1)
						result = root
					default:
						t.Errorf("unexpected request %s", r.URL.Path)
						http.NotFound(w, r)
						return
					}
					if err := json.NewEncoder(w).Encode(result); err != nil {
						t.Error(err)
					}
				})
				infos, err := FetchUserGroupInfos(t.Context(), c, "person")
				if err != nil || len(infos) != wantCount {
					t.Fatalf("memberships %v, error %v; want %d", infos, err, wantCount)
				}
				foundRoot := false
				for _, info := range infos {
					if info.ID == "keycloak/root" && info.Name == rootPath {
						foundRoot = true
					}
				}
				if !foundRoot {
					t.Fatalf("root ID and native path missing from %v", infos)
				}
				if got := detailReads.Load(); got != wantReads {
					t.Fatalf("detail reads %d, want %d", got, wantReads)
				}
			})
		}
	}
}
