# EnvGate

EnvGate is a local-first AI secret firewall for development workflows. It keeps
environment files encrypted at rest, asks for scoped approval before injecting
secrets into commands, and writes encrypted tamper-evident local audit logs.

EnvGate's current MVP is passive and explicit-call only. It does not scan all
terminal input, hook your shell, or monitor arbitrary commands. Secrets are
protected when agents and users run secret-bearing commands through `envgate run`
or request access through `envgate request`.

## Local workflow

```bash
./install.sh
envgate init --project ambienta
envgate unlock --ttl 8h
envgate allow --profile dev --scope always --agent codex
envgate dev --agent codex
```

## Current CLI surface

```bash
envgate setup --yes --project ambienta
envgate setup --yes --project ambienta --unlock-ttl 8h
envgate setup --yes --project ambienta --no-unlock
envgate init
envgate init --bare
envgate import <source-env-file>
envgate register <project>
envgate use <project>
envgate projects list
envgate projects show <project>
envgate projects register <project>
envgate projects use <project>
envgate projects remove <project>
envgate broker status
envgate broker stop
envgate broker socket-path
envgate worktrees list --project ambienta
envgate worktrees allow-root --project ambienta /path/to/worktrees
envgate worktrees remove-root --project ambienta /path/to/worktrees
envgate worktrees approve <request-id>
envgate worktrees deny <request-id>
envgate env list --project ambienta
envgate env set --project ambienta KEY=value
envgate env unset --project ambienta KEY
envgate env unlock
envgate env lock
envgate env export --output .env.export
envgate request --profile dev --json --no-prompt --agent claude --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x
envgate request --agent codex --action "Run migration" --command "pnpm payload migrate" --env DATABASE_URL
envgate request --json --no-prompt --agent claude --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --action "Run dev" --command "pnpm dev" --env DATABASE_URL
envgate approve <request-id> --scope session --agent-mediated --json
envgate approve <request-id> --scope once --confirm-critical --agent-mediated --json
envgate deny <request-id> --agent-mediated --json
envgate allow --profile dev --scope always --agent codex
envgate allow --scope always --agent codex --command "pnpm dev" --env DATABASE_URL
envgate grants list
envgate grants revoke <grant-id>
envgate grants prune
envgate run --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
envgate run --agent codex --action "Run dev server" --env DATABASE_URL -- pnpm dev
envgate dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
envgate migrate --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
envgate edit
envgate unlock --ttl 8h
envgate lock
envgate doctor
envgate logs
envgate logs view executions
envgate logs verify
envgate logs verify --full
envgate logs export executions --output executions.log
envgate teardown --yes
envgate teardown --yes --restore-env
```

`envgate init` is the recommended human onboarding command. When `.env` or
`.env.vault` exists, it runs the guided setup flow: config, vault import or
validation, locked `.env`, registry, profiles, agent docs, `.gitignore`, and an
initial run unlock session. Use `envgate init --bare` only for the older
config-only behavior. `envgate setup --yes` remains the script-friendly path.

Setup creates the first run unlock session by default, using the same
PIN/passphrase entered for the vault import. `envgate unlock --ttl 8h` is still
used later to refresh an expired unlock or after `envgate lock`.

`envgate unlock` also starts or refreshes the on-demand local broker. The broker
keeps active unlock/signing capability in memory and listens on a private Unix
socket under `~/.envgate/run/envgate.sock`. It is started on demand, not
installed as a daemon, and it does not watch the filesystem or scan terminal
input.

For `--json --no-prompt` agent flows, EnvGate requires complete context:
`--agent`, `--worktree`, `--branch`, `--git-remote`, `--commit`, `--action`, and
either `--profile` or exact `--command` plus `--env` names. EnvGate verifies the
claimed worktree, branch, remote, and commit locally before approving, signing,
reusing grants, or executing.
For local repositories without an `origin` remote, pass `--git-remote ""`
explicitly; omitting `--git-remote` is still treated as missing context.

Approval grants are stored locally under `~/.envgate/sessions/grants.jsonl`.
Reusable grants are signed with a per-project Ed25519 approval key, so editing
the command, env names, scope, expiry, branch, agent, or signature makes the
grant invalid and forces re-approval. Session grants expire after 8 hours.
Branch and always grants persist until manually removed or superseded. Grants
skip approval prompts only; an active unlock session or fresh PIN/passphrase is
still required when `envgate run` injects secrets.

Creating reusable approvals also requires an active broker unlock session
because EnvGate signs approval receipts from broker-held signing capability. If
an agent gets `signing_key_unavailable` or JSON with
`"status": "unlock_required"`, the human should run:

```bash
envgate unlock --ttl 8h
```

Critical preflight findings are treated differently. Commands that look like
secret dumps, runtime env inspection, direct secret echoing, encoding,
clipboard copying, or network exfiltration cannot receive durable grants.
`envgate request --json --no-prompt` returns `confirmationRequired: true`, a
warning payload, and only `once`/`deny` approval options. The approval command
must include `--confirm-critical`, and `envgate run` ignores matching
session/branch/always grants for critical commands.

EnvGate also scans declared `--action` text because agents show it to users
during approval. Prompt-injection or approval-coercion language forces manual
approval and removes the `always` scope. Action text that combines secret
references with URLs or network transfer hints becomes a critical finding.

## Local files

Project-local:

```txt
.env                  # EnvGate locked marker by default; plaintext only after envgate env unlock
.envgate.json
.env.vault
.env.example
AGENTS.md or CLAUDE.md
```

`envgate setup` creates or updates these files, imports `.env` into
`.env.vault`, replaces plaintext `.env` with an EnvGate locked marker file,
registers the project, updates `.gitignore`, and writes `dev` and `migrate`
profiles into `.envgate.json`. If `CLAUDE.md` already exists, EnvGate appends
the agent instructions there; otherwise it uses `AGENTS.md`.

Profile entries are explicit. Agents can request a profile name without seeing
the vault contents, and EnvGate expands the command and exact env names locally:

```json
{
  "profiles": {
    "dev": {
      "command": "pnpm dev",
      "env": ["DATABASE_URL", "PAYLOAD_SECRET"],
      "defaultScope": "always",
      "action": "Run local development server"
    },
    "migrate": {
      "command": "pnpm payload migrate",
      "env": ["DATABASE_URL", "PAYLOAD_SECRET"],
      "defaultScope": "branch",
      "action": "Run database migration"
    }
  }
}
```

New `.envgate.json` files generate profiles only. They can still contain
`presets` if you add advanced raw-command policy rules later. Profiles are the
user/agent-facing shortcut layer for commands like `envgate dev`,
`envgate migrate`, and `envgate run --profile dev`.
Generated profiles include only env names verified in `.env.vault`; EnvGate
does not add compatibility guesses such as `DATABASE_URL` when the vault only
contains `DATABASE_URI`. Profile env lists are also treated as the normal scope
declaration, so routine profile requests do not emit `env.scope_deviation`.

Global:

```txt
~/.envgate/registry.json
~/.envgate/logs/
~/.envgate/sessions/
~/.envgate/requests/
~/.envgate/keys/
~/.envgate/cache/
~/.envgate/run/
~/.envgate/worktrees.json
~/.envgate/agents.json
```

EnvGate creates its own state directories with private permissions where the
platform supports them: directories are `0700` and state files are `0600`.
Encrypted audit logs use a local random key stored at
`~/.envgate/cache/log-key.json`; the normal log path does not use the OS
Keychain.
Approval private keys are encrypted locally with the project PIN/passphrase.
During `envgate unlock`, EnvGate loads signing capability into broker memory so
later agent subprocesses can request signed approvals without receiving the
vault passphrase or private key.

Trusted worktree roots are configured globally. A new worktree is auto-bound
only when an EnvGate command is contacted from a path under an allowed root and
Git verification matches the registered project. Weak matches produce a
worktree approval request instead of silently receiving secrets.

## Security boundary

EnvGate does not stop commands that bypass it:

```bash
cat .env
printenv
pnpm dev
```

The intended workflow is:

```txt
keep .env locked unless explicitly using envgate env unlock for manual work
run secret-bearing commands through envgate run
view encrypted audit logs through envgate logs view with the PIN/passphrase when needed
```

When using `envgate run`, put every EnvGate flag before `--`. Everything after
`--` is treated as the child command:

```bash
# Correct
envgate run --agent codex --action "Run dev" --env DATABASE_URL --json --no-prompt -- pnpm dev

# Wrong: --json and --no-prompt are passed to pnpm, not EnvGate
envgate run --agent codex --action "Run dev" --env DATABASE_URL -- pnpm dev --json --no-prompt
```

Automatic worktree env delivery means scoped process env injection through the
broker. It does not write plaintext `.env` files for agents; plaintext `.env`
remains explicit through `envgate env unlock`.

Vault secrets may be a 4+ character PIN/passphrase. Four digits are a
convenience minimum for local-only use; use a longer passphrase if `.env.vault`
may leave the machine.

Signed approvals and hash-chained logs are tamper-evident, not undeletable. A
same-user process can still remove local files if the OS permits it.

## Development

```bash
cargo fmt --check
cargo check
cargo test -- --test-threads=1
cargo run -- --help
```

Local install and usage instructions are available in
[docs/local-install-and-usage.md](docs/local-install-and-usage.md).
The full feature and command reference is available in
[docs/features-and-commands.md](docs/features-and-commands.md).
Env file concepts and local templates are documented in
[docs/env-files.md](docs/env-files.md).
Simple visual user-flow infographics are available in
[docs/infographics.md](docs/infographics.md).

Coverage gate:

```bash
./scripts/coverage.sh
```

Release scaffolding is included under `.github/workflows/release.yml`. Until a
GitHub repo slug is finalized, `./install.sh` builds locally. After that, set
`ENVGATE_GITHUB_REPO=owner/envgate` to install a published release artifact.
