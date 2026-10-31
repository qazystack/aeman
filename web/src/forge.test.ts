import { describe, expect, it } from "vitest";

import { forgeCopy } from "./forge";

const github = {
  kind: "github",
  label: "GitHub",
  cli: "gh",
  host: "github.com",
  signInTitle: "Sign in to aeman",
  signInLead: "Connect your GitHub account to open the board.",
  signInButton: "Sign in with GitHub",
  noTokenHint: "No GitHub token — run aeman login, or gh auth login, in the terminal where aeman runs.",
  connectHint: "Sign in with GitHub on first use (OAuth, no token stored).",
};

const gitlab = {
  kind: "gitlab",
  label: "GitLab",
  cli: "glab",
  host: "gitlab.com",
  signInTitle: "Sign in to aeman",
  signInLead: "Connect your GitLab account to open the board.",
  signInButton: "Sign in with GitLab",
  noTokenHint: "No GitLab token — run aeman login, or glab auth login, in the terminal where aeman runs.",
  connectHint: "Sign in with GitLab on first use (OAuth, no token stored).",
};

const forgejo = {
  kind: "gitea",
  label: "Forgejo",
  cli: "",
  host: "codeberg.org",
  signInTitle: "Sign in to aeman",
  signInLead: "Connect your Forgejo account to open the board.",
  signInButton: "Sign in with Forgejo",
  noTokenHint: "No Forgejo token — run aeman login in the terminal where aeman runs.",
  connectHint: "Sign in with Forgejo on first use (OAuth, no token stored).",
};

describe("forgeCopy", () => {
  it("spells a Forgejo board's copy under its own name, with no CLI to name", () => {
    expect(forgeCopy({ forge: "gitea", forgeLabel: "Forgejo", cli: "", forgeHost: "codeberg.org" })).toEqual(forgejo);
  });

  it("calls a Gitea named only by kind Gitea and never offers a tool's auth login", () => {
    const copy = forgeCopy({ forge: "gitea", forgeHost: "git.example.org" });
    expect(copy.kind).toBe("gitea");
    expect(copy.label).toBe("Gitea");
    expect(copy.cli).toBe("");
    expect(copy.host).toBe("git.example.org");
    expect(copy.noTokenHint).toBe("No Gitea token — run aeman login in the terminal where aeman runs.");
    expect(copy.noTokenHint).not.toContain("auth login");
  });

  it("is GitHub when there is no config yet (the sign-in gate renders before /api/config answers)", () => {
    expect(forgeCopy(undefined)).toEqual(github);
    expect(forgeCopy(null)).toEqual(github);
  });

  it("is GitHub when an older server names no forge at all", () => {
    expect(forgeCopy({})).toEqual(github);
  });

  it("spells the GitHub copy from an explicit GitHub config", () => {
    expect(
      forgeCopy({ forge: "github", forgeLabel: "GitHub", cli: "gh", forgeHost: "github.com" }),
    ).toEqual(github);
  });

  it("spells the GitLab copy from a gitlab.com config", () => {
    expect(
      forgeCopy({ forge: "gitlab", forgeLabel: "GitLab", cli: "glab", forgeHost: "gitlab.com" }),
    ).toEqual(gitlab);
  });

  it("fills the GitLab label, CLI and host in when the server names only the kind", () => {
    expect(forgeCopy({ forge: "gitlab" })).toEqual(gitlab);
  });

  it("puts a self-hosted host into the repository placeholder and keeps the rest", () => {
    const copy = forgeCopy({ forge: "gitlab", forgeHost: "git.example.com" });
    expect(copy.host).toBe("git.example.com");
    expect(copy.signInButton).toBe("Sign in with GitLab");
    expect(copy.noTokenHint).toBe(gitlab.noTokenHint);
  });

  it("lets the server's label and CLI win over the kind's defaults (an enterprise GitHub)", () => {
    const copy = forgeCopy({
      forge: "github",
      forgeLabel: "GitHub Enterprise",
      cli: "gh",
      forgeHost: "github.example.com",
    });
    expect(copy.label).toBe("GitHub Enterprise");
    expect(copy.signInLead).toBe("Connect your GitHub Enterprise account to open the board.");
    expect(copy.signInButton).toBe("Sign in with GitHub Enterprise");
    expect(copy.connectHint).toBe(
      "Sign in with GitHub Enterprise on first use (OAuth, no token stored).",
    );
  });

  it("treats empty strings as absent, so a zero-valued field falls back to the kind's default", () => {
    expect(forgeCopy({ forge: "gitlab", forgeLabel: "", cli: "", forgeHost: "" })).toEqual(gitlab);
  });

  it("keeps the sign-in title forge-neutral", () => {
    expect(forgeCopy({ forge: "gitlab" }).signInTitle).toBe(github.signInTitle);
  });
  it("names the OIDC provider in the sign-in copy, and keeps the forge as the board's host", () => {
    const copy = forgeCopy({ forge: "gitlab", forgeLabel: "GitLab", forgeHost: "git.example.test", signInName: "Corp SSO" });
    expect(copy.signInButton).toBe("Sign in with Corp SSO");
    expect(copy.signInLead).toBe("Connect your Corp SSO account to open the board.");
    expect(copy.connectHint).toBe("Sign in with Corp SSO on first use (OAuth, no token stored).");
    expect(copy.kind).toBe("gitlab");
    expect(copy.label).toBe("GitLab");
    expect(copy.host).toBe("git.example.test");
  });

  it("falls back to the forge when the provider's name is empty on the wire", () => {
    expect(forgeCopy({ signInName: "" })).toEqual(github);
  });
});
