package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aenix-io/aeman/internal/forge"
)

// Signing in with Gitea (or Forgejo, which keeps the API): the login
// redirect goes to the instance's /login/oauth/authorize with Gitea's
// scopes, the callback exchanges the code at /login/oauth/access_token, the
// session is the Gitea login, and the config names the forge, its label,
// its host and no token tool — the SPA's copy then tells a local user to
// run `aeman login` only. The instance is mounted at a subpath, and the
// person who signed in is known to the directory without a further call.
func TestGiteaSignInFlow(t *testing.T) {
	var forms []string
	gt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/git/login/oauth/access_token":
			body, _ := io.ReadAll(r.Body)
			forms = append(forms, string(body))
			if !strings.Contains(string(body), "grant_type=authorization_code") || !strings.Contains(string(body), "redirect_uri=") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gt-token", "token_type": "bearer", "refresh_token": "gt-refresh", "expires_in": 3600})
		case "/git/api/v1/user":
			if r.Header.Get("Authorization") != "token gt-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"login": "dana", "full_name": "Dana Scully", "avatar_url": "https://gitea.example/avatars/dana"})
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(gt.Close)

	srv, err := New(Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Forge:  forge.NewGitea(gt.URL+"/git", "Forgejo"),
		Auth:   &OAuthConfig{ClientID: "gt-client", ClientSecret: "gt-secret", BaseURL: testBaseURL},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var cfg struct {
		Mode, Forge, ForgeLabel, ForgeHost, CLI, Login string
		Authenticated                                  bool
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	wantHost := strings.TrimPrefix(gt.URL, "http://")
	if cfg.Mode != "oauth" || cfg.Forge != "gitea" || cfg.ForgeLabel != "Forgejo" || cfg.CLI != "" || cfg.ForgeHost != wantHost || cfg.Authenticated {
		t.Fatalf("config before sign-in = %+v (want host %s)", cfg, wantHost)
	}

	rec = httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, gt.URL+"/git/login/oauth/authorize?") ||
		!strings.Contains(loc, "scope=read%3Auser+read%3Arepository") || !strings.Contains(loc, "response_type=code") {
		t.Fatalf("login: %d %s", rec.Code, loc)
	}
	var state string
	for _, c := range rec.Result().Cookies() {
		if c.Name == stateCookie {
			state = c.Value
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: state})
	rec = httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if len(forms) != 1 || !strings.Contains(forms[0], "client_id=gt-client") || !strings.Contains(forms[0], "code=abc") {
		t.Fatalf("token forms = %v", forms)
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c.Value
		}
	}
	req = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	rec = httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Authenticated || cfg.Login != "dana" {
		t.Fatalf("config after sign-in = %+v", cfg)
	}
	if m := srv.people.member("dana"); m.Name != "Dana Scully" || m.AvatarURL != "https://gitea.example/avatars/dana" {
		t.Fatalf("the signed-in person in the directory = %+v", m)
	}
}
