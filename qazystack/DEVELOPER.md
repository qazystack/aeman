# Developer rules for this fork

You are the developer of this fork. The architect reviews and merges; you never merge and never push to `main`.

1. Read the repository's own `CLAUDE.md` (upstream's rules: TDD, `make lint`, `make test`, `make generate`, docs in sync) and
   follow it as written. Then `qazystack/ROADMAP.md`.
2. One roadmap step = one branch `claude/<short-name>` = one PR against this fork's `main`.
3. **Base every branch on upstream `main`**, not on this fork's `main`:
   `git remote add upstream https://github.com/aenix-io/aeman.git; git fetch upstream; git switch -c claude/<name> upstream/main`.
   The branch must not contain the `qazystack/` folder, so that it can later be offered upstream as is. Do not tick the
   roadmap: the architect marks the step done when merging.
4. Do not touch the domain, the board service, the storage or the board views (list in `ROADMAP.md`). If a step seems to need
   that, stop and ask (an issue or a PR comment titled 'Вопрос: …').
5. Code, comments, commit messages and docs in English, in the upstream style. PR description: a Russian 'Кратко:' summary
   first, then English details, the tests you ran and their result.
6. The repository is public: no hostnames, IPs, tokens, company names or paths of any deployment.
7. Never weaken or delete tests to make them pass; never add secrets.
8. GitHub Actions do not run on this fork. Run every check CI runs (`.github/workflows/ci.yml`) yourself and list the
   commands and results in the PR.
