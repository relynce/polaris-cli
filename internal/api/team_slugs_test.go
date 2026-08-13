package api

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/revelara-ai/rvl-cli/internal/config"
)

// TestFetchTeamSlugs pins the best-effort contract (po-77b6w.1): the org's
// slugs on 200, nil on any failure so callers skip the did-you-mean
// instead of blocking a submission, and empty-but-non-nil when the org
// simply has no teams yet.
func TestFetchTeamSlugs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var gotPath, gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"slugs":["checkout","payments"],"total":2}`))
		}))
		defer srv.Close()

		got := FetchTeamSlugs(&config.Config{APIURL: srv.URL, APIKey: "test-key"})
		if want := []string{"checkout", "payments"}; !reflect.DeepEqual(got, want) {
			t.Errorf("slugs = %v, want %v", got, want)
		}
		if gotPath != "/api/v1/teams/slugs" {
			t.Errorf("path = %q, want /api/v1/teams/slugs", gotPath)
		}
		if gotAuth != "Bearer test-key" {
			t.Errorf("auth = %q, want Bearer test-key", gotAuth)
		}
	})

	t.Run("org with no teams yet returns empty non-nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"slugs":[],"total":0}`))
		}))
		defer srv.Close()
		got := FetchTeamSlugs(&config.Config{APIURL: srv.URL, APIKey: "k"})
		if got == nil || len(got) != 0 {
			t.Errorf("got %v, want empty non-nil slice", got)
		}
	})

	t.Run("server error returns nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}))
		defer srv.Close()
		if got := FetchTeamSlugs(&config.Config{APIURL: srv.URL, APIKey: "k"}); got != nil {
			t.Errorf("got %v, want nil on 500", got)
		}
	})

	t.Run("old server without the endpoint returns nil", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()
		if got := FetchTeamSlugs(&config.Config{APIURL: srv.URL, APIKey: "k"}); got != nil {
			t.Errorf("got %v, want nil on 404", got)
		}
	})

	t.Run("unconfigured returns nil without network", func(t *testing.T) {
		if got := FetchTeamSlugs(nil); got != nil {
			t.Errorf("got %v, want nil for nil config", got)
		}
		if got := FetchTeamSlugs(&config.Config{}); got != nil {
			t.Errorf("got %v, want nil for empty config", got)
		}
	})
}
