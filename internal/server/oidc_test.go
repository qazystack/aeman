package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aenix-io/aeman/pkg/gitstore"
)

// fakeIdP is enough of an OpenID Connect provider for the sign-in: the
// discovery document, the key set, the token endpoint (codes, PKCE,
// refreshes) and userinfo. Its people and their groups can change under a
// running server, and a person's authorization can be revoked.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu sync.Mutex
	// issuer is what the discovery document claims (the server's own URL
	// unless a test lies).
	issuer string
	// signWith signs the ID tokens; a key other than key is a bad signature.
	signWith *rsa.PrivateKey
	// tamper edits an ID token's claims before it is signed.
	tamper func(map[string]any)
	// groupsInUserinfoOnly leaves the groups out of the ID token.
	groupsInUserinfoOnly bool
	people               map[string]*idpPerson
	codes                map[string]idpCode
	access               map[string]string // access token -> login
	refresh              map[string]string // refresh token -> login
	userinfoCalls        int
	n                    int
}

type idpPerson struct {
	name    string
	groups  []string
	revoked bool
}

type idpCode struct {
	login, challenge, nonce, redirect string
}

const (
	oidcClientID     = "aeman-client"
	oidcClientSecret = "aeman-secret"
)

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key, signWith: key, people: map[string]*idpPerson{},
		codes: map[string]idpCode{}, access: map[string]string{}, refresh: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.issuer = f.srv.URL
	return f
}

func (f *fakeIdP) person(login, name string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.people[login] = &idpPerson{name: name, groups: groups}
}

func (f *fakeIdP) setGroups(login string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.people[login].groups = groups
}

func (f *fakeIdP) revoke(login string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.people[login].revoked = true
}

func (f *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"userinfo_endpoint":                     f.srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/keys":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	case "/token":
		f.token(w, r)
	case "/userinfo":
		f.userinfoCalls++
		login, ok := f.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok || f.people[login].revoked {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "sub-" + login, "preferred_username": login, "groups": f.people[login].groups})
	default:
		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != oidcClientID || secret != oidcClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		return
	}
	var login, nonce string
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		c, ok := f.codes[r.PostFormValue("code")]
		delete(f.codes, r.PostFormValue("code"))
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.PostFormValue("redirect_uri") != c.redirect {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		login, nonce = c.login, c.nonce
	case "refresh_token":
		l, ok := f.refresh[r.PostFormValue("refresh_token")]
		if !ok || f.people[l].revoked {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		login = l
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.n++
	at, rt := "at-"+login+"-"+strconv.Itoa(f.n), "rt-"+login+"-"+strconv.Itoa(f.n)
	f.access[at], f.refresh[rt] = login, login
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": at, "refresh_token": rt, "token_type": "Bearer", "expires_in": 3600,
		"id_token": f.idToken(login, nonce),
	})
}

// idToken signs an ID token for a person. Called with f.mu held.
func (f *fakeIdP) idToken(login, nonce string) string {
	p := f.people[login]
	claims := map[string]any{
		"iss": f.issuer, "aud": oidcClientID, "sub": "sub-" + login,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"preferred_username": login, "name": p.name, "email": login + "@example.test",
		"picture": "https://idp.example.test/" + login + ".png",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if !f.groupsInUserinfoOnly {
		claims["groups"] = p.groups
	}
	if f.tamper != nil {
		f.tamper(claims)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.signWith},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// authorize is the provider's sign-in page: the person at the keyboard
// signs in as login, and the provider sends them back with a code. It
// checks what the request must carry — PKCE S256, a nonce, our client.
func (f *fakeIdP) authorize(t *testing.T, location, login string) (code, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, f.srv.URL+"/authorize?") {
		t.Fatalf("sign-in went to %q, want the provider's authorize endpoint", location)
	}
	q := u.Query()
	for k, want := range map[string]string{"response_type": "code", "client_id": oidcClientID, "code_challenge_method": "S256"} {
		if q.Get(k) != want {
			t.Fatalf("authorize %s = %q, want %q (%s)", k, q.Get(k), want, location)
		}
	}
	if q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorize lacks the PKCE challenge, the nonce or the state: %s", location)
	}
	if !slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		t.Fatalf("authorize scope = %q, want openid in it", q.Get("scope"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	code = "code-" + strconv.Itoa(f.n)
	f.codes[code] = idpCode{login: login, challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	return code, q.Get("state")
}

// oidcServer is an OIDC-mode server over two domains: shared (the primary,
// project portal) and closed (project secret).
func oidcServer(t *testing.T, idp *fakeIdP, rules []OIDCRule, sessionFile string) *Server {
	t.Helper()
	shared, closed := gitRemoteN(t, "shared"), gitRemoteN(t, "closed")
	seedGitRemote(t, shared)
	seedClosedRemote(t, closed)
	return oidcServerOver(t, idp, rules, sessionFile, shared, closed)
}

func oidcServerOver(t *testing.T, idp *fakeIdP, rules []OIDCRule, sessionFile string, shared, closed gitstore.Remote) *Server {
	t.Helper()
	srv, err := New(Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: &OAuthConfig{
			ClientID: oidcClientID, ClientSecret: oidcClientSecret, BaseURL: testBaseURL,
			SessionFile: sessionFile,
			OIDC:        &OIDCConfig{Issuer: idp.srv.URL, Name: "Corp SSO", Access: rules},
		},
		Git: &GitConfig{Repos: []RepoSpec{{Name: "shared", URL: shared.URL}, {Name: "closed", URL: closed.URL}},
			DataDir: t.TempDir(), Committer: gitstore.Identity{Name: "aeman", Email: "aeman@test"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	srv.gitBE.git.pushDelay = 0
	srv.handler = conforms(t, srv.handler)
	return srv
}

var teamRules = []OIDCRule{
	{Domain: "shared", Group: "devs", Write: true},
	{Domain: "closed", Group: "ops", Write: true},
	{Domain: "*", Group: "auditors"},
}

// signInOIDC drives the browser flow: /auth/login, the provider's page,
// /auth/callback. It returns the callback's answer.
func signInOIDC(t *testing.T, srv *Server, idp *fakeIdP, login string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/auth/login: %d %s", rec.Code, rec.Body.String())
	}
	var cookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == stateCookie {
			cookie = c.Value
		}
	}
	code, state := idp.authorize(t, rec.Header().Get("Location"), login)
	if state != cookie {
		t.Fatalf("the provider got state %q, the browser holds %q", state, cookie)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code="+code+"&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: stateCookie, Value: cookie})
	rec = httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, req)
	return rec
}

func sessionOf(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			return c.Value
		}
	}
	return ""
}

func mustSignInOIDC(t *testing.T, srv *Server, idp *fakeIdP, login string) string {
	t.Helper()
	rec := signInOIDC(t, srv, idp, login)
	sid := sessionOf(rec)
	if rec.Code != http.StatusFound || sid == "" {
		t.Fatalf("sign-in as %s: %d %s (no session)", login, rec.Code, rec.Body.String())
	}
	return sid
}

func getWithSession(srv *Server, sid, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, req)
	return rec
}

// G81 — the whole browser sign-in through an OIDC provider: discovery, the
// code flow with PKCE and a nonce, the ID token checked, a session for the
// provider's login, the sign-in button's name in /api/config, and a board
// that shows exactly the domains the visitor's groups open.
func TestOIDCBrowserSignIn(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("alice", "Alice Liddell", "devs")
	srv := oidcServer(t, idp, teamRules, "")

	cfg := getWithSession(srv, "", "/api/config")
	if !strings.Contains(cfg.Body.String(), `"signInName":"Corp SSO"`) || strings.Contains(cfg.Body.String(), `"authenticated":true`) {
		t.Fatalf("config before sign-in: %s", cfg.Body.String())
	}

	sid := mustSignInOIDC(t, srv, idp, "alice")
	cfg = getWithSession(srv, sid, "/api/config")
	if !strings.Contains(cfg.Body.String(), `"authenticated":true`) || !strings.Contains(cfg.Body.String(), `"login":"alice"`) {
		t.Fatalf("config after sign-in: %s", cfg.Body.String())
	}
	rec := getWithSession(srv, sid, "/api/v1/board")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"portal"`) || strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatalf("alice (devs) must see shared and not closed: %d %s", rec.Code, rec.Body.String())
	}
	// The person who signed in is on the board as the provider describes them.
	if m := srv.people.member("alice"); m.Name != "Alice Liddell" || m.AvatarURL != "https://idp.example.test/alice.png" {
		t.Fatalf("alice in the directory = %+v", m)
	}
}

// G81 — groups that only userinfo carries are read from there.
func TestOIDCGroupsFromUserinfo(t *testing.T) {
	idp := newFakeIdP(t)
	idp.groupsInUserinfoOnly = true
	idp.person("alice", "Alice", "devs", "ops")
	srv := oidcServer(t, idp, teamRules, "")
	sid := mustSignInOIDC(t, srv, idp, "alice")
	rec := getWithSession(srv, sid, "/api/v1/views/all/cards")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "three-closed") {
		t.Fatalf("alice (devs+ops, from userinfo) must see the closed card: %d %s", rec.Code, rec.Body.String())
	}
}

// G81 — an ID token that does not verify opens no session: a foreign
// issuer, another audience, a nonce this sign-in did not send, a signature
// the provider's keys do not check, an expired token.
func TestOIDCRefusesAnIDTokenThatDoesNotVerify(t *testing.T) {
	cases := map[string]func(f *fakeIdP){
		"issuer":    func(f *fakeIdP) { f.tamper = func(c map[string]any) { c["iss"] = "https://elsewhere.test" } },
		"audience":  func(f *fakeIdP) { f.tamper = func(c map[string]any) { c["aud"] = "another-client" } },
		"nonce":     func(f *fakeIdP) { f.tamper = func(c map[string]any) { c["nonce"] = "replayed" } },
		"expired":   func(f *fakeIdP) { f.tamper = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() } },
		"signature": func(f *fakeIdP) { f.signWith, _ = rsa.GenerateKey(rand.Reader, 2048) },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.person("alice", "Alice", "devs")
			srv := oidcServer(t, idp, teamRules, "")
			spoil(idp)
			rec := signInOIDC(t, srv, idp, "alice")
			if rec.Code != http.StatusUnauthorized || sessionOf(rec) != "" {
				t.Fatalf("callback with a bad %s: %d %s, want 401 and no session", name, rec.Code, rec.Body.String())
			}
		})
	}
}

// G81 — the discovery document must name the configured issuer: a provider
// that claims to be someone else is not signed in with at all.
func TestOIDCDiscoveryMustNameTheConfiguredIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	idp.issuer = "https://impostor.test"
	srv := oidcServer(t, idp, teamRules, "")
	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("/auth/login with a lying discovery document: %d %s, want 502", rec.Code, rec.Body.String())
	}
}

// G81 — the issuer is https; plain http only on a loopback host.
func TestCheckOIDCIssuer(t *testing.T) {
	for issuer, ok := range map[string]bool{
		"https://sso.example.test":            true,
		"https://sso.example.test/realms/eng": true,
		"http://127.0.0.1:5556/dex":           true,
		"http://localhost:8080":               true,
		"http://[::1]:8080":                   true,
		"http://sso.example.test":             false,
		"ftp://sso.example.test":              false,
		"sso.example.test":                    false,
		"":                                    false,
	} {
		if err := CheckOIDCIssuer(issuer); (err == nil) != ok {
			t.Errorf("CheckOIDCIssuer(%q) = %v, want ok=%v", issuer, err, ok)
		}
	}
}

// G81 — deny by default: a visitor whose groups no rule names is refused
// right after signing in, and no session is opened.
func TestOIDCDeniesAVisitorNoRuleOpensADomainTo(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("mallory", "Mallory", "marketing")
	idp.person("nobody", "No Groups")
	srv := oidcServer(t, idp, teamRules, "")
	for _, login := range []string{"mallory", "nobody"} {
		rec := signInOIDC(t, srv, idp, login)
		if rec.Code != http.StatusForbidden || sessionOf(rec) != "" {
			t.Fatalf("%s: %d %s, want 403 and no session", login, rec.Code, rec.Body.String())
		}
	}
	if _, ok := srv.auth.directory.get("mallory"); ok {
		t.Fatal("a refused visitor must not enter the directory")
	}
}

// G81 — what the rules grant: read or write, write implying read, rules
// for one domain adding up, "*" naming every domain, and nothing at all for
// a group no rule names.
func TestRightsOfTheAccessRules(t *testing.T) {
	domains := []string{"shared", "closed"}
	rules := []OIDCRule{
		{Domain: "shared", Group: "readers"},
		{Domain: "shared", Group: "writers", Write: true},
		{Domain: "closed", Group: "readers"},
		{Domain: "*", Group: "admins", Write: true},
		{Domain: "*", Group: "auditors"},
	}
	type want struct{ read, write []string }
	for name, c := range map[string]struct {
		groups []string
		want   want
	}{
		"no groups":              {nil, want{}},
		"an unnamed group":       {[]string{"marketing"}, want{}},
		"read on two domains":    {[]string{"readers"}, want{read: domains}},
		"write implies read":     {[]string{"writers"}, want{read: []string{"shared"}, write: []string{"shared"}}},
		"rules add up":           {[]string{"readers", "writers"}, want{read: domains, write: []string{"shared"}}},
		"star writes everywhere": {[]string{"admins"}, want{read: domains, write: domains}},
		"star reads everywhere":  {[]string{"auditors"}, want{read: domains}},
	} {
		r := rightsOf(rules, domains, c.groups)
		for _, d := range domains {
			if r.canRead(d) != slices.Contains(c.want.read, d) || r.canWrite(d) != slices.Contains(c.want.write, d) {
				t.Errorf("%s: %s read=%v write=%v, want read=%v write=%v", name, d, r.canRead(d), r.canWrite(d),
					slices.Contains(c.want.read, d), slices.Contains(c.want.write, d))
			}
		}
		if r.primary != "shared" {
			t.Errorf("%s: primary = %q, want the first domain", name, r.primary)
		}
	}
}

// G81 — a reader may look but not write: the domain's write is refused.
func TestOIDCReadRuleDoesNotWrite(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("audrey", "Audrey", "auditors")
	srv := oidcServer(t, idp, teamRules, "")
	sid := mustSignInOIDC(t, srv, idp, "audrey")
	if rec := getWithSession(srv, sid, "/api/v1/views/all/cards"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "three-closed") {
		t.Fatalf("an auditor reads every domain: %d %s", rec.Code, rec.Body.String())
	}
	r, err := srv.access.rights(context.Background(), "", "audrey")
	if err != nil || r.canWrite("shared") || r.canWrite("closed") || !r.canRead("closed") {
		t.Fatalf("auditor rights = %+v, %v; want read everywhere, write nowhere", r, err)
	}
}

// G81 — someone taken out of a group at the provider loses the domain once
// the answer is older than accessTTL, and not before: the groups are asked
// again (userinfo with the session's token) when the cache expires.
func TestOIDCGroupRemovedAtTheProviderLosesTheDomainAfterTheTTL(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("bob", "Bob", "devs", "ops")
	srv := oidcServer(t, idp, teamRules, "")
	oa := srv.access.(*oidcAccess)
	now := time.Now()
	oa.now = func() time.Time { return now }
	sid := mustSignInOIDC(t, srv, idp, "bob")
	if rec := getWithSession(srv, sid, "/api/v1/board"); !strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatalf("bob (ops) sees the closed project: %s", rec.Body.String())
	}
	idp.setGroups("bob", "devs")
	now = now.Add(accessTTL - time.Second)
	if rec := getWithSession(srv, sid, "/api/v1/board"); !strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatalf("within accessTTL the answer stands: %s", rec.Body.String())
	}
	now = now.Add(2 * time.Second)
	rec := getWithSession(srv, sid, "/api/v1/board")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"secret"`) || !strings.Contains(rec.Body.String(), `"portal"`) {
		t.Fatalf("after accessTTL bob has lost closed and kept shared: %d %s", rec.Code, rec.Body.String())
	}
	if p, _ := srv.auth.directory.get("bob"); !slices.Equal(p.Groups, []string{"devs"}) {
		t.Fatalf("the directory keeps the provider's latest groups: %v", p.Groups)
	}
	// Losing every group is losing the board.
	idp.setGroups("bob")
	now = now.Add(accessTTL)
	if rec := getWithSession(srv, sid, "/api/v1/board"); rec.Code != http.StatusForbidden {
		t.Fatalf("bob with no group left: %d %s, want 403", rec.Code, rec.Body.String())
	}
}

// G81 — a session the provider has revoked (userinfo answers 401, and the
// refresh token is refused too) ends when the groups are next asked: the
// API answers authorizationExpired and the visitor is signed out.
func TestOIDCRevokedSessionEnds(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("bob", "Bob", "devs")
	srv := oidcServer(t, idp, teamRules, "")
	oa := srv.access.(*oidcAccess)
	now := time.Now()
	oa.now = func() time.Time { return now }
	sid := mustSignInOIDC(t, srv, idp, "bob")
	idp.revoke("bob")
	if rec := getWithSession(srv, sid, "/api/v1/board"); rec.Code != http.StatusOK {
		t.Fatalf("within accessTTL nobody is asked: %d", rec.Code)
	}
	now = now.Add(accessTTL + time.Second)
	rec := getWithSession(srv, sid, "/api/v1/board")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked: %d %s, want 401", rec.Code, rec.Body.String())
	}
	if p := decodeProblem(t, rec); p.Code != "authorizationExpired" {
		t.Fatalf("code = %q, want authorizationExpired", p.Code)
	}
	if cfg := getWithSession(srv, sid, "/api/config"); strings.Contains(cfg.Body.String(), `"authenticated":true`) {
		t.Fatalf("the revoked session must be gone: %s", cfg.Body.String())
	}
}

// G81 — a userinfo 401 that the refresh token cures is not the end: the
// session renews and carries on.
func TestOIDCRefusedTokenIsRenewedBeforeTheSessionEnds(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("bob", "Bob", "devs")
	srv := oidcServer(t, idp, teamRules, "")
	oa := srv.access.(*oidcAccess)
	now := time.Now()
	oa.now = func() time.Time { return now }
	sid := mustSignInOIDC(t, srv, idp, "bob")
	// The provider forgets the access token (a restart, a key rotation);
	// the refresh token still stands.
	idp.mu.Lock()
	for at := range idp.access {
		delete(idp.access, at)
	}
	idp.mu.Unlock()
	now = now.Add(accessTTL + time.Second)
	if rec := getWithSession(srv, sid, "/api/v1/board"); rec.Code != http.StatusOK {
		t.Fatalf("a refusal the refresh cures: %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// G81 — who can be assigned: the people in the directory whose groups open
// the domain. Someone who never signed in is not offered.
func TestOIDCReadersComeFromTheDirectory(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("alice", "Alice", "devs")
	idp.person("bob", "Bob", "devs", "ops")
	srv := oidcServer(t, idp, teamRules, "")
	mustSignInOIDC(t, srv, idp, "alice")
	mustSignInOIDC(t, srv, idp, "bob")
	logins := []string{"alice", "bob", "zed"}
	for domain, want := range map[string][]string{"shared": {"alice", "bob"}, "closed": {"bob"}} {
		got, err := srv.access.readers(context.Background(), domain, logins)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("readers(%s) = %v, %v; want %v", domain, got, err, want)
		}
	}
	if _, err := srv.access.readers(context.Background(), "nope", logins); err == nil {
		t.Fatal("an unknown domain is an error")
	}
	if m := srv.people.member("zed"); m.Name != "" || m.AvatarURL != "" {
		t.Fatalf("a login nobody signed in as is a bare login: %+v", m)
	}
}

// G81 — the directory lives in the session file next to the sessions and
// survives a restart; it holds names and groups, never a token.
func TestOIDCDirectoryIsPersistedWithoutTokens(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("alice", "Alice", "devs")
	file := filepath.Join(t.TempDir(), "sessions.json")
	shared, closed := gitRemoteN(t, "shared"), gitRemoteN(t, "closed")
	seedGitRemote(t, shared)
	seedClosedRemote(t, closed)
	srv := oidcServerOver(t, idp, teamRules, file, shared, closed)
	mustSignInOIDC(t, srv, idp, "alice")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"alice"`) || !strings.Contains(string(raw), `"devs"`) {
		t.Fatalf("the session file lacks the directory: %s", raw)
	}
	if strings.Contains(string(raw), "at-alice") || strings.Contains(string(raw), "rt-alice") {
		t.Fatalf("the session file holds a token in the clear: %s", raw)
	}
	_ = srv.Close()
	again := oidcServerOver(t, idp, teamRules, file, shared, closed)
	got, err := again.access.readers(context.Background(), "shared", []string{"alice"})
	if err != nil || !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("after a restart readers = %v, %v; want alice", got, err)
	}
}

// G81 — a rule naming a domain the board does not have is a start-up
// error, not a rule that quietly denies everyone.
func TestOIDCRuleForAnUnknownDomainIsRefused(t *testing.T) {
	idp := newFakeIdP(t)
	shared := gitRemoteN(t, "shared")
	seedGitRemote(t, shared)
	_, err := New(Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: &OAuthConfig{ClientID: oidcClientID, ClientSecret: oidcClientSecret, BaseURL: testBaseURL,
			OIDC: &OIDCConfig{Issuer: idp.srv.URL, Access: []OIDCRule{{Domain: "shraed", Group: "devs"}}}},
		Git: &GitConfig{Repos: []RepoSpec{{Name: "shared", URL: shared.URL}}, DataDir: t.TempDir(),
			Committer: gitstore.Identity{Name: "aeman", Email: "aeman@test"}},
	})
	if err == nil || !strings.Contains(err.Error(), "shraed") {
		t.Fatalf("New = %v, want the unknown domain named", err)
	}
}

// G81 — the access rule's flag form.
func TestParseOIDCAccess(t *testing.T) {
	for in, want := range map[string]OIDCRule{
		"shared=devs:write":      {Domain: "shared", Group: "devs", Write: true},
		"shared=devs:read":       {Domain: "shared", Group: "devs"},
		"*=auditors:read":        {Domain: "*", Group: "auditors"},
		"closed = org:ops:write": {Domain: "closed", Group: "org:ops", Write: true},
	} {
		got, err := ParseOIDCAccess(in)
		if err != nil || got != want {
			t.Errorf("ParseOIDCAccess(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "shared", "shared=devs", "shared=devs:admin", "=devs:read", "shared=:read"} {
		if _, err := ParseOIDCAccess(bad); err == nil {
			t.Errorf("ParseOIDCAccess(%q) must fail", bad)
		}
	}
}

// G81 — the MCP authorization signs in through the provider the same way
// as the browser (PKCE and a nonce on the provider leg, the access rules
// deciding), and ends in an MCP access token that is a live session.
func TestOIDCMCPSignIn(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("alice", "Alice", "devs")
	idp.person("mallory", "Mallory", "marketing")
	srv := oidcServer(t, idp, teamRules, "")

	authorize := func(login string) *httptest.ResponseRecorder {
		clientID := registerClient(t, srv, testRedirectURI)
		verifier := "pkce-verifier-sufficiently-long-0123456789"
		aq := url.Values{}
		aq.Set("client_id", clientID)
		aq.Set("redirect_uri", testRedirectURI)
		aq.Set("response_type", "code")
		aq.Set("code_challenge", pkceChallenge(verifier))
		aq.Set("code_challenge_method", "S256")
		aq.Set("state", "client-state")
		rec := do(t, srv, http.MethodGet, "/oauth/authorize?"+aq.Encode(), "")
		if rec.Code != http.StatusFound {
			t.Fatalf("authorize: %d %s", rec.Code, rec.Body.String())
		}
		code, state := idp.authorize(t, rec.Header().Get("Location"), login)
		cb := do(t, srv, http.MethodGet, "/auth/callback?code="+code+"&state="+state, "")
		if cb.Code != http.StatusFound {
			t.Fatalf("callback: %d %s", cb.Code, cb.Body.String())
		}
		loc, _ := url.Parse(cb.Header().Get("Location"))
		if mcpCode := loc.Query().Get("code"); mcpCode != "" {
			return redeemToken(t, srv, mcpCode, verifier, testRedirectURI, clientID)
		}
		rec = httptest.NewRecorder()
		rec.Code = http.StatusFound
		rec.Header().Set("Location", cb.Header().Get("Location"))
		return rec
	}

	rec := authorize("alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("token response: %s", rec.Body.String())
	}
	if s, ok := srv.auth.sessionByID(context.Background(), tok.AccessToken); !ok || s.login != "alice" {
		t.Fatalf("the MCP token is alice's session: %+v %v", s, ok)
	}

	// The access rules decide here as well: a visitor no domain is open to
	// goes back to the client with access_denied, and no code.
	rec = authorize("mallory")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Fatalf("mallory's MCP authorization: %s, want access_denied", rec.Header().Get("Location"))
	}
}
