// The forge is the identity provider and the remote the board lives on —
// GitHub, GitLab, or Gitea (Forgejo too: one adapter, its own label). The server names it in /api/config; every piece of copy
// that says "GitHub" somewhere in the UI is spelled from here so a GitLab
// board never tells its visitors to sign in with GitHub. An older server sends
// none of the fields: that is GitHub, exactly as before.

import type { AppConfig } from "./api/client";

export type ForgeKind = "github" | "gitlab" | "gitea";

export type ForgeConfig = Pick<AppConfig, "forge" | "forgeLabel" | "cli" | "forgeHost" | "signInName">;

export interface ForgeCopy {
  kind: ForgeKind;
  /** Human name of the forge: "GitHub", "GitLab", or whatever the server calls
   *  its self-hosted one. */
  label: string;
  /** The forge's own CLI, "gh" or "glab" — one of the sources a local run reads its token from, after the environment and the OS keychain. Empty for Gitea, which has no such tool. */
  cli: string;
  /** The host repositories live on: "github.com", "gitlab.com", or the
   *  self-hosted instance. */
  host: string;
  signInTitle: string;
  signInLead: string;
  signInButton: string;
  /** The local-mode banner when no source holds a token. */
  noTokenHint: string;
  /** The MCP caption in the Connect dialog. */
  connectHint: string;
}

const DEFAULTS: Record<ForgeKind, { label: string; cli: string; host: string }> = {
  github: { label: "GitHub", cli: "gh", host: "github.com" },
  gitlab: { label: "GitLab", cli: "glab", host: "gitlab.com" },
  // Gitea has no public instance to default to; the server always names
  // the host it runs against, and gitea.com is only the placeholder.
  gitea: { label: "Gitea", cli: "", host: "gitea.com" },
};

const KINDS: readonly ForgeKind[] = ["github", "gitlab", "gitea"];

/** forgeCopy spells the forge-specific copy from the server's config. Missing
 *  fields (and empty ones — a zero value on the wire) fall back to the kind's
 *  defaults; a missing kind is GitHub. */
export function forgeCopy(config: ForgeConfig | null | undefined): ForgeCopy {
  const kind: ForgeKind = KINDS.find((k) => k === config?.forge) ?? "github";
  const defaults = DEFAULTS[kind];
  const label = config?.forgeLabel || defaults.label;
  const cli = config?.cli || defaults.cli;
  const host = config?.forgeHost || defaults.host;
  // A server that signs people in through an OIDC provider names it: the
  // sign-in copy is the provider's, while the forge stays the board's host.
  const sso = config?.signInName;
  return {
    kind,
    label,
    cli,
    host,
    signInTitle: "Sign in to aeman",
    signInLead: `Connect your ${sso || label} account to open the board.`,
    signInButton: `Sign in with ${sso || label}`,
    noTokenHint: cli
      ? `No ${label} token — run aeman login, or ${cli} auth login, in the terminal where aeman runs.`
      : `No ${label} token — run aeman login in the terminal where aeman runs.`,
    connectHint: `Sign in with ${sso || label} on first use (OAuth, no token stored).`,
  };
}
