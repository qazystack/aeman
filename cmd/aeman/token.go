package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"

	"github.com/aenix-io/aeman/internal/server"
)

// runToken is `aeman token new`: a fresh service token for a client that
// cannot sign in through a browser, and the line the server's
// AEMAN_SERVICE_TOKENS_FILE needs for it. The token is printed once and
// never stored anywhere — the file holds only its SHA-256.
func runToken(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "new" {
		return errors.New("usage: aeman token new --login <login> [--groups g1,g2] [--name <display name>]")
	}
	fs := flag.NewFlagSet("token new", flag.ContinueOnError)
	login := fs.String("login", "", "the login the token acts as — commits made with it are authored with it")
	groups := fs.String("groups", "", "OIDC mode only: the groups the --oidc-access rules read for this token, comma-separated")
	name := fs.String("name", "", "OIDC mode only: the display name the boards show for this login (default: the login)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *login == "" || strings.HasPrefix(*login, "#") || strings.IndexFunc(*login, unicode.IsSpace) >= 0 {
		return errors.New("--login is required: one word, the login the token acts as")
	}
	line := *login
	if *groups != "" {
		for _, g := range strings.Split(*groups, ",") {
			if g == "" || strings.IndexFunc(g, unicode.IsSpace) >= 0 {
				return fmt.Errorf("--groups %q: comma-separated group names, no spaces, none empty", *groups)
			}
		}
	}
	if *name != "" && strings.TrimSpace(*name) == "" {
		return errors.New("--name names nothing")
	}
	token, hash, err := server.NewServiceToken()
	if err != nil {
		return err
	}
	line += " " + hash
	if *groups != "" {
		line += " groups=" + *groups
	}
	if *name != "" {
		// Percent-encoded, so a name with spaces stays one field.
		line += " name=" + url.PathEscape(strings.TrimSpace(*name))
	}
	_, err = fmt.Fprintf(out, "# The token: hand it to the client now. It is not shown again, and the server never stores it.\n%s\n"+
		"# The line to add to AEMAN_SERVICE_TOKENS_FILE (the server re-reads the file when it changes):\n%s\n", token, line)
	return err
}
