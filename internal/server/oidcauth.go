package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/aenix-io/aeman/internal/forge"
)

// handleOIDCLogin starts a browser sign-in through the OIDC provider: the
// state in the usual cookie, the PKCE verifier and the nonce kept here for
// the callback, and the visitor sent to the provider.
func (a *authManager) handleOIDCLogin(w http.ResponseWriter, r *http.Request, state string) {
	flow := loginFlow{verifier: oauth2.GenerateVerifier(), nonce: randToken(), created: time.Now()}
	dest, err := a.oidc.authCodeURL(r.Context(), state, flow.nonce, flow.verifier)
	if err != nil {
		a.log.Error("oidc provider unavailable", "err", err)
		writeJSONError(w, http.StatusBadGateway, "the sign-in provider is unavailable")
		return
	}
	a.mu.Lock()
	a.pruneEphemeralLocked()
	a.loginFlows[state] = flow
	a.mu.Unlock()
	a.setCookie(w, stateCookie, state, 600)
	http.Redirect(w, r, dest, http.StatusFound)
}

// oidcSignIn finishes a sign-in through the provider, browser's or MCP's
// alike: the code exchanged and the ID token checked, the visitor admitted
// by the access rules or refused, and — once admitted — remembered in the
// directory and the board's people. The status is the HTTP answer for the
// error.
func (a *authManager) oidcSignIn(ctx context.Context, code, verifier, nonce string) (ghGrant, string, int, error) {
	grant, person, err := a.oidc.signIn(ctx, code, verifier, nonce)
	if err != nil {
		a.log.Warn("oidc sign-in refused", "err", err)
		if errors.Is(err, errIDTokenRefused) {
			return ghGrant{}, "", http.StatusUnauthorized, errors.New("sign-in refused: the identity token did not verify")
		}
		return ghGrant{}, "", http.StatusBadGateway, errors.New("sign-in with " + a.label() + " failed")
	}
	if a.admit != nil {
		if err := a.admit(person); err != nil {
			a.log.Info("oidc sign-in refused by the access rules", "login", person.Login, "groups", person.Groups)
			return ghGrant{}, "", http.StatusForbidden, err
		}
	}
	if a.directory != nil {
		a.directory.remember(person, time.Now())
	}
	if a.learned != nil {
		a.learned(forge.User{Login: person.Login, Name: person.Name, AvatarURL: person.AvatarURL})
	}
	return grant, person.Login, 0, nil
}
