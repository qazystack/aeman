package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aenix-io/aeman/pkg/apiserver"
	"github.com/aenix-io/aeman/pkg/board"
	"github.com/aenix-io/aeman/pkg/gitstore"
)

// G83 — in the OIDC mode a service-token line is a board member: its login,
// with the line's groups through the --oidc-access rules, counts among a
// domain's readers like a person who signed in, and it is listed in
// metadata.members — with the line's name=, else its login — even before
// any card names it. So an agent can be picked as an assignee or a reviewer
// the day its token is issued. The forge mode is unchanged: there the forge
// decides who is a member.

const agentToken = "aeman_svc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// oidcTokenServer is the two-domain OIDC board with a service-tokens file.
func oidcTokenServer(t *testing.T, idp *fakeIdP, path string) *Server {
	t.Helper()
	shared, closed := gitRemoteN(t, "shared"), gitRemoteN(t, "closed")
	seedGitRemote(t, shared)
	seedClosedRemote(t, closed)
	srv, err := New(Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: &OAuthConfig{
			ClientID: oidcClientID, ClientSecret: oidcClientSecret, BaseURL: testBaseURL,
			OIDC: &OIDCConfig{Issuer: idp.srv.URL, Name: "Corp SSO", Access: teamRules},
		},
		ServiceTokensFile: path,
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

type boardPeople struct {
	members map[string]string   // login → display name
	readers map[string][]string // domain → logins
}

// peopleOf reads GET /board as a signed-in person: who metadata.members
// lists, by name, and who each domain the visitor reads names as readers.
func peopleOf(t *testing.T, srv *Server, sid string) boardPeople {
	t.Helper()
	rec := getWithSession(srv, sid, "/api/v1/board")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /board: %d %s", rec.Code, rec.Body.String())
	}
	var b struct {
		Metadata struct {
			Members []struct{ Login, Name string }
			Domains []struct {
				Name    string
				Members []string
			}
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	out := boardPeople{members: map[string]string{}, readers: map[string][]string{}}
	for _, m := range b.Metadata.Members {
		out.members[m.Login] = m.Name
	}
	for _, d := range b.Metadata.Domains {
		out.readers[d.Name] = d.Members
	}
	return out
}

// G83 — the name= field: percent-encoded (a space is %20), at most once,
// not empty, and — like groups= — only in the OIDC mode, the one mode that
// reads it.
func TestServiceTokenName(t *testing.T) {
	h := tokenHash(botToken)
	entries, err := parseServiceTokens([]byte("bot " + h + " groups=devs name=Review%20Bot\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].name != "Review Bot" || !slices.Equal(entries[0].groups, []string{"devs"}) {
		t.Fatalf("entries = %+v", entries)
	}
	if entries, err := parseServiceTokens([]byte("bot " + h + "\n")); err != nil || entries[0].name != "" {
		t.Fatalf("no name= is no name: %+v %v", entries, err)
	}
	for name, bad := range map[string]string{
		"empty name":   "bot " + h + " name=\n",
		"twice name":   "bot " + h + " name=a name=b\n",
		"bad escape":   "bot " + h + " name=Review%zzBot\n",
		"blank name":   "bot " + h + " name=%20\n",
		"control char": "bot " + h + " name=a%0Ab\n",
	} {
		if _, err := parseServiceTokens([]byte(bad)); err == nil {
			t.Errorf("%s: %q was accepted", name, bad)
		}
	}
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+h+" name=Bot\n")
	if _, err := openServiceTokens(path, false, nil); err == nil || !strings.Contains(err.Error(), "name=") {
		t.Fatalf("name= on a forge-mode server: %v; want a refusal naming name=", err)
	}
}

// G83 — an agent that exists only as a token line is a member the moment
// the line is there: listed with its name, a reader of exactly the domains
// its groups open, and a card created with it as the assignee is accepted.
// Once the line is gone it is offered nowhere — no domain names it as a
// reader, and a token login no card names drops out of the members — while
// the card already assigned to it keeps the login.
func TestServiceTokenLoginIsABoardMemberInOIDCMode(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("bob", "Bob", "devs", "ops")
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+" groups=devs\n"+
		"agent "+tokenHash(agentToken)+" groups=devs name=Review%20Agent\n"+
		"audit "+tokenHash(readToken)+" groups=auditors\n")
	srv := oidcTokenServer(t, idp, path)
	sid := mustSignInOIDC(t, srv, idp, "bob")

	p := peopleOf(t, srv, sid)
	if p.members["agent"] != "Review Agent" || p.members["audit"] != "audit" || p.members["bot"] != "bot" {
		t.Fatalf("members = %v; want agent as Review Agent, audit and bot by their logins", p.members)
	}
	if !slices.Contains(p.readers["shared"], "agent") || slices.Contains(p.readers["closed"], "agent") {
		t.Fatalf("readers = %v; agent (devs) reads shared, not closed", p.readers)
	}
	if !slices.Contains(p.readers["shared"], "audit") || !slices.Contains(p.readers["closed"], "audit") {
		t.Fatalf("readers = %v; audit (auditors, *) reads both", p.readers)
	}

	body := `{"title":"for the agent","team":"portal","zone":"planned","dates":{"start":"2026-08-27"},"assignees":["agent"]}`
	rec := asService(t, srv, botToken, http.MethodPost, "/api/v1/views/team/cards", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a card assigned to the agent: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Metadata struct{ UID string }
		Spec     struct{ Assignees []string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(created.Spec.Assignees, []string{"agent"}) {
		t.Fatalf("assignees = %v, want [agent]", created.Spec.Assignees)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.store.waitDrained(ctx)

	writeTokens(t, path, "bot "+tokenHash(botToken)+" groups=devs\n")
	touch(t, path, time.Second)
	p = peopleOf(t, srv, sid)
	for domain, readers := range p.readers {
		if slices.Contains(readers, "agent") || slices.Contains(readers, "audit") {
			t.Fatalf("readers(%s) = %v after the lines were removed", domain, readers)
		}
	}
	if _, listed := p.members["audit"]; listed {
		t.Fatalf("members = %v; a removed token login no card names is not a member", p.members)
	}
	if _, listed := p.members["agent"]; !listed {
		t.Fatalf("members = %v; the card assigned to agent still names it", p.members)
	}
	rec = getWithSession(srv, sid, "/api/v1/views/all/cards")
	if !strings.Contains(rec.Body.String(), created.Metadata.UID) || !strings.Contains(rec.Body.String(), `"agent"`) {
		t.Fatalf("the assigned card keeps its assignee: %s", rec.Body.String())
	}
}

// G83 — a login that is both a person who signed in and a token line is the
// person: the directory's name and groups decide what the board shows and
// which domains it reads as a member. The line's groups still decide what
// the token itself may do.
func TestAPersonWinsOverATokenLineOfTheSameLogin(t *testing.T) {
	idp := newFakeIdP(t)
	idp.person("alice", "Alice", "devs")
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "alice "+tokenHash(agentToken)+" groups=ops name=Alice%27s%20Bot\n")
	srv := oidcTokenServer(t, idp, path)
	mustSignInOIDC(t, srv, idp, "alice")

	for domain, want := range map[string][]string{"shared": {"alice"}, "closed": {}} {
		got, err := srv.access.readers(context.Background(), domain, []string{"alice"})
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("readers(%s) = %v, %v; want %v (the person's devs, not the line's ops)", domain, got, err, want)
		}
	}
	if m := srv.people.member("alice"); m.Name != "Alice" {
		t.Fatalf("member(alice) = %+v; want the person's name", m)
	}
	r, err := srv.serviceRights(context.Background(), serviceAccount{login: "alice", groups: []string{"ops"}})
	if err != nil || !r.canWrite("closed") || r.canRead("shared") {
		t.Fatalf("the token's own rights = %+v, %v; want the line's ops", r, err)
	}
}

// G83 — the forge mode is unchanged: the forge, not the tokens file, says
// who reads a domain, so a token login is listed only once a card names it.
func TestServiceTokenLoginIsNotListedInForgeMode(t *testing.T) {
	var calls atomic.Int32
	gh := fakePermissions(t, map[string]map[string]string{
		"bot":    {"shared": "write", "closed": "read"},
		"reader": {"shared": "read"},
	}, &calls)
	path := filepath.Join(t.TempDir(), "tokens")
	writeTokens(t, path, "bot "+tokenHash(botToken)+"\nreader "+tokenHash(readToken)+"\n")
	srv := forgeServiceServer(t, gh, path)
	rec := asService(t, srv, botToken, http.MethodGet, "/api/v1/board", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /board: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"reader"`) {
		t.Fatalf("a token login no card names is listed in the forge mode: %s", rec.Body.String())
	}
}

// G83 — what GET /board and the watch stream's Load frame both list: the
// assignees MembersOf found, plus each token login not among them, with the
// roster's capacity and the people hook's name, sorted by login. A login
// already listed is not listed twice, and no extra login leaves the list
// as it was.
func TestWithTokenMembers(t *testing.T) {
	b := board.Board{People: map[string]board.Person{"agent": {Capacity: 5}}}
	listed := []apiserver.Member{{Login: "bob", Name: "Bob", Load: 3}, {Login: "zed"}}
	named := func(login string) apiserver.Member {
		return apiserver.Member{Login: login, Name: strings.ToUpper(login)}
	}

	got := withTokenMembers(b, slices.Clone(listed), []string{"agent", "bob"}, named)
	want := []apiserver.Member{{Login: "agent", Name: "AGENT", Capacity: 5}, {Login: "bob", Name: "Bob", Load: 3}, {Login: "zed"}}
	if !slices.Equal(got, want) {
		t.Fatalf("withTokenMembers = %+v, want %+v", got, want)
	}
	if got := withTokenMembers(b, slices.Clone(listed), nil, named); !slices.Equal(got, listed) {
		t.Fatalf("no extra logins changed the list: %+v", got)
	}
}
