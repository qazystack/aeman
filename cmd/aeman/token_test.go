package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// `aeman token new` prints a fresh service token (aeman_svc_ and 32 random
// bytes as hex) and the line the operator adds to AEMAN_SERVICE_TOKENS_FILE:
// the login and the token's SHA-256 — never the token itself — plus the
// groups when given. The two are the only non-comment lines, so a script
// can take them apart; two runs never print the same token.
func TestTokenNewPrintsATokenAndTheLineForTheFile(t *testing.T) {
	parse := func(out string) (token, line string) {
		var rest []string
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				rest = append(rest, l)
			}
		}
		if len(rest) != 2 {
			t.Fatalf("output = %q; want the token and the line", out)
		}
		return rest[0], rest[1]
	}
	var out strings.Builder
	if err := runToken([]string{"new", "--login", "agent-bot"}, &out); err != nil {
		t.Fatal(err)
	}
	token, line := parse(out.String())
	if !strings.HasPrefix(token, "aeman_svc_") || len(token) != len("aeman_svc_")+64 {
		t.Fatalf("token = %q; want aeman_svc_ and 64 hex digits", token)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(token, "aeman_svc_")); err != nil {
		t.Fatalf("token body is not hex: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	if line != "agent-bot "+hex.EncodeToString(sum[:]) {
		t.Fatalf("line = %q; want the login and the token's SHA-256", line)
	}
	if strings.Contains(line, token) {
		t.Fatal("the line must not hold the token")
	}

	out.Reset()
	if err := runToken([]string{"new", "--login", "agent-bot", "--groups", "devs,ops"}, &out); err != nil {
		t.Fatal(err)
	}
	again, line := parse(out.String())
	if again == token {
		t.Fatal("two runs printed the same token")
	}
	if !strings.HasSuffix(line, " groups=devs,ops") {
		t.Fatalf("line = %q; want the groups", line)
	}

	for name, args := range map[string][]string{
		"no login":         {"new"},
		"login with space": {"new", "--login", "agent bot"},
		"comment login":    {"new", "--login", "#bot"},
		"group with space": {"new", "--login", "bot", "--groups", "a b"},
		"empty group":      {"new", "--login", "bot", "--groups", "a,,b"},
		"no verb":          {},
		"unknown verb":     {"rotate"},
	} {
		if err := runToken(args, &strings.Builder{}); err == nil {
			t.Errorf("%s: %q was accepted", name, args)
		}
	}
}
