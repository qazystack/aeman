package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// gitea is one Gitea or Forgejo instance — Forgejo keeps the Gitea API v1,
// so one adapter serves both and only the label tells them apart. OAuth
// lives under /login/oauth and REST under /api/v1 of one base URL (which
// may carry a subpath); a repository is always owner/name; a visitor's
// rights are the repository's permissions block; a member is anyone whose
// collaborator permission reads (ownership and org teams included, as the
// forge computes it); avatars are served by the instance, found through the
// user directory.
type gitea struct {
	base  string // https://gitea.example.org, or https://host/gitea
	label string // "Gitea" or "Forgejo"
}

// NewGitea is the Gitea (or Forgejo) instance at base, shown as label —
// "Gitea" when empty.
func NewGitea(base, label string) Forge {
	if label == "" {
		label = "Gitea"
	}
	return &gitea{base: strings.TrimRight(base, "/"), label: label}
}

func (g *gitea) Kind() Kind    { return Gitea }
func (g *gitea) Label() string { return g.label }

// Host is the instance's host, port and all, lower-cased and without the
// path — the same key GitLab's Host is, for the same reasons.
func (g *gitea) Host() string {
	u, err := url.Parse(g.base)
	if err != nil || u.Host == "" {
		return strings.ToLower(g.base)
	}
	return strings.ToLower(u.Host)
}

func (g *gitea) AuthorizeURL() string { return g.base + "/login/oauth/authorize" }
func (g *gitea) TokenURL() string     { return g.base + "/login/oauth/access_token" }
func (g *gitea) api() string          { return g.base + "/api/v1" }

// DefaultScopes: read:user for who-am-i, read:repository for permissions
// and collaborators. A visitor's token never pushes — the server's own
// credential does — so it asks for nothing that writes. A Gitea older than
// the scoped OAuth tokens ignores the parameter.
func (g *gitea) DefaultScopes() string { return "read:user read:repository" }

func (g *gitea) ExchangeForm(clientID, secret, code, redirectURI string) url.Values {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	return form
}

// RefreshForm renews an access token (Gitea's live an hour by default).
func (g *gitea) RefreshForm(clientID, secret, refresh, _ string) url.Values {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	return form
}

func (g *gitea) get(ctx context.Context, client *http.Client, token, path string) (*http.Response, error) {
	// The path is the operator's repository or a board member's login,
	// escaped, under the instance's API base.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.api()+path, nil) //nolint:gosec // see above
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aeman")
	return client.Do(req) //nolint:gosec // see above
}

// giteaUser is the user shape Gitea returns everywhere.
type giteaUser struct {
	Login     string `json:"login"`
	FullName  string `json:"full_name"`
	AvatarURL string `json:"avatar_url"`
}

func (u giteaUser) person() Person {
	return Person{Login: u.Login, Name: u.FullName, AvatarURL: u.AvatarURL}
}

func (g *gitea) User(ctx context.Context, client *http.Client, token string) (User, error) {
	resp, err := g.get(ctx, client, token, "/user")
	if err != nil {
		return User{}, err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		_ = resp.Body.Close()
		return User{}, ErrBadToken
	case resp.StatusCode != http.StatusOK:
		_ = resp.Body.Close()
		return User{}, fmt.Errorf("user endpoint returned %s", resp.Status)
	}
	var u giteaUser
	if err := decodeJSON(resp, &u); err != nil {
		return User{}, err
	}
	return User{Login: u.Login, Name: u.FullName, AvatarURL: u.AvatarURL}, nil
}

// RepoRef is owner/name: the last two segments of the URL's path, so an
// instance mounted at a subpath names the same repository.
func (g *gitea) RepoRef(repoURL string) (string, error) {
	parts := repoPath(repoURL)
	if len(parts) < 2 {
		return "", fmt.Errorf("repository url %q has no owner/repo path", repoURL)
	}
	parts = parts[len(parts)-2:]
	return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]), nil
}

// Access asks GET /repos/{owner}/{repo} as the visitor: the permissions
// block says pull (reads) and push (writes); a public repository answers
// pull for anyone. A 404 is what Gitea says for a repository the visitor
// cannot see.
func (g *gitea) Access(ctx context.Context, client *http.Client, token, repoURL string) (read, write bool, err error) {
	ref, err := g.RepoRef(repoURL)
	if err != nil {
		return false, false, err
	}
	resp, err := g.get(ctx, client, token, "/repos/"+ref)
	if err != nil {
		return false, false, err
	}
	switch {
	case throttled(resp):
		_ = resp.Body.Close()
		return false, false, fmt.Errorf("%w: %s", ErrRateLimited, resp.Status)
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusForbidden:
		_ = resp.Body.Close()
		return false, false, nil
	case resp.StatusCode == http.StatusUnauthorized:
		_ = resp.Body.Close()
		return false, false, ErrBadToken
	case resp.StatusCode/100 != 2:
		_ = resp.Body.Close()
		return false, false, fmt.Errorf("forge answered %s", resp.Status)
	}
	var body struct {
		Private     bool `json:"private"`
		Permissions *struct {
			Admin bool `json:"admin"`
			Push  bool `json:"push"`
			Pull  bool `json:"pull"`
		} `json:"permissions"`
	}
	if err := decodeJSON(resp, &body); err != nil {
		return false, false, err
	}
	if p := body.Permissions; p != nil {
		write = p.Push || p.Admin
		read = p.Pull || write
	}
	return read || !body.Private, write, nil
}

// Readers asks each login's collaborator permission with the server's
// credential. Gitea computes it from ownership, collaboration and org teams
// alike, so the answer is the visitor's effective right; "none" does not
// read, and a login the forge does not know is skipped. The answer carries
// the user, so the name and the avatar come with it.
func (g *gitea) Readers(ctx context.Context, client *http.Client, serverToken, repoURL string, logins []string) (map[string]Person, error) {
	if serverToken == "" {
		return nil, fmt.Errorf("no server credential to ask the forge with")
	}
	ref, err := g.RepoRef(repoURL)
	if err != nil {
		return nil, err
	}
	out := map[string]Person{}
	for _, login := range logins {
		if login == "" {
			continue
		}
		resp, err := g.get(ctx, client, serverToken, "/repos/"+ref+"/collaborators/"+url.PathEscape(login)+"/permission")
		if err != nil {
			return nil, err
		}
		switch {
		case throttled(resp):
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%w: %s", ErrRateLimited, resp.Status)
		case resp.StatusCode == http.StatusNotFound:
			_ = resp.Body.Close()
			continue
		case resp.StatusCode/100 != 2:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("forge answered %s", resp.Status)
		}
		var body struct {
			Permission string    `json:"permission"`
			User       giteaUser `json:"user"`
		}
		if err := decodeJSON(resp, &body); err != nil {
			return nil, err
		}
		switch body.Permission {
		case "read", "write", "admin", "owner":
			p := body.User.person()
			if p.Login == "" {
				p.Login = login
			}
			out[login] = p
		}
	}
	return out, nil
}

// Lookup asks the user directory for a login.
func (g *gitea) Lookup(ctx context.Context, client *http.Client, token, login string) (Person, error) {
	if login == "" {
		return Person{}, ErrNotFound
	}
	resp, err := g.get(ctx, client, token, "/users/"+url.PathEscape(login))
	if err != nil {
		return Person{}, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		_ = resp.Body.Close()
		return Person{}, ErrNotFound
	case resp.StatusCode/100 != 2:
		_ = resp.Body.Close()
		return Person{}, fmt.Errorf("forge answered %s", resp.Status)
	}
	var u giteaUser
	if err := decodeJSON(resp, &u); err != nil {
		return Person{}, err
	}
	if u.Login == "" {
		return Person{}, ErrNotFound
	}
	return u.person(), nil
}

// GitAuth: Gitea takes a token over HTTPS as the password, whatever the
// user name; "oauth2" is the one GitLab insists on, and Gitea accepts it.
func (g *gitea) GitAuth(token string) *githttp.BasicAuth {
	return &githttp.BasicAuth{Username: "oauth2", Password: token}
}
