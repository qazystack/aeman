package server

import "github.com/aenix-io/aeman/internal/forge"

// cliName is the forge's command-line tool, for the copy that tells a
// person how to sign in on a single-user server: gh, glab — or "" for a
// forge with no tool that hands out its token (Gitea), where the copy
// names `aeman login` alone.
func cliName(f forge.Forge) string {
	switch {
	case f != nil && f.Kind() == forge.GitLab:
		return "glab"
	case f != nil && f.Kind() == forge.Gitea:
		return ""
	}
	return "gh"
}
