# Ward

Ward is a local-first AI secret firewall for development workflows. It keeps
environment files encrypted at rest, asks for scoped approval before injecting
secrets into commands, and writes encrypted tamper-evident local audit logs.

Ward's current MVP is passive and explicit-call only. It does not scan all
terminal input, hook your shell, or monitor arbitrary commands. Secrets are
protected when agents and users run secret-bearing commands through `ward run`
or request access through `ward request`.

## Local workflow

```bash
./install.sh
ward init --project ambienta
ward unlock --ttl 8h
ward allow --profile dev --scope always --agent codex
ward dev --agent codex
```

## Current CLI surface

```bash
ward setup --yes --project ambienta
ward setup --yes --project ambienta --unlock-ttl 8h
ward setup --yes --project ambienta --no-unlock
ward init
ward init --bare
ward import <source-env-file>
ward register <project>
ward use <project>
ward projects list
ward projects show <project>
ward projects register <project>
ward projects use <project>
ward projects remove <project>
ward broker status
ward broker stop
ward broker socket-path
ward worktrees list --project ambienta
ward worktrees allow-root --project ambienta /path/to/worktrees
ward worktrees remove-root --project ambienta /path/to/worktrees
ward worktrees approve <request-id>
ward worktrees deny <request-id>
ward env list --project ambienta
ward env set --project ambienta KEY=value
ward env unset --project ambienta KEY
ward env unlock
ward env lock
ward env export --output .env.export
ward request --profile dev --json --no-prompt --agent claude --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x
ward request --agent codex --action "Run migration" --command "pnpm payload migrate" --env DATABASE_URL
ward request --json --no-prompt --agent claude --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --action "Run dev" --command "pnpm dev" --env DATABASE_URL
ward approve <request-id> --scope session --agent-mediated --json
ward approve <request-id> --scope once --confirm-critical --agent-mediated --json
ward deny <request-id> --agent-mediated --json
ward allow --profile dev --scope always --agent codex
ward allow --scope always --agent codex --command "pnpm dev" --env DATABASE_URL
ward grants list
ward grants revoke <grant-id>
ward grants prune
ward run --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
ward run --agent codex --action "Run dev server" --env DATABASE_URL -- pnpm dev
ward dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
ward migrate --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
ward edit
ward unlock --ttl 8h
ward lock
ward doctor
ward logs
ward logs view executions
ward logs verify
ward logs verify --full
ward logs export executions --output executions.log
ward teardown --yes
ward teardown --yes --restore-env
```

`ward init` is the recommended human onboarding command. When `.env` or
`.env.vault` exists, it runs the guided setup flow: config, vault import or
validation, locked `.env`, registry, profiles, agent docs, `.gitignore`, and an
initial run unlock session. Use `ward init --bare` only for the older
config-only behavior. `ward setup --yes` remains the script-friendly path.

Setup creates the first run unlock session by default, using the same
PIN/passphrase entered for the vault import. `ward unlock --ttl 8h` is still
used later to refresh an expired unlock or after `ward lock`.

`ward unlock` also starts or refreshes the on-demand local broker. The broker
keeps active unlock/signing capability in memory and listens on a private Unix
socket under `~/.ward/run/ward.sock`. It is started on demand, not
installed as a daemon, and it does not watch the filesystem or scan terminal
input.

For `--json --no-prompt` agent flows, Ward requires complete context:
`--agent`, `--worktree`, `--branch`, `--git-remote`, `--commit`, `--action`, and
either `--profile` or exact `--command` plus `--env` names. Ward verifies the
claimed worktree, branch, remote, and commit locally before approving, signing,
reusing grants, or executing.
For local repositories without an `origin` remote, pass `--git-remote ""`
explicitly; omitting `--git-remote` is still treated as missing context.

Approval grants are stored locally under `~/.ward/sessions/grants.jsonl`.
Reusable grants are signed with a per-project Ed25519 approval key, so editing
the command, env names, scope, expiry, branch, agent, or signature makes the
grant invalid and forces re-approval. Session grants expire after 8 hours.
Branch and always grants persist until manually removed or superseded. Grants
skip approval prompts only; an active unlock session or fresh PIN/passphrase is
still required when `ward run` injects secrets.

Creating reusable approvals also requires an active broker unlock session
because Ward signs approval receipts from broker-held signing capability. If
an agent gets `signing_key_unavailable` or JSON with
`"status": "unlock_required"`, the human should run:

```bash
ward unlock --ttl 8h
```

Critical preflight findings are treated differently. Commands that look like
secret dumps, runtime env inspection, direct secret echoing, encoding,
clipboard copying, or network exfiltration cannot receive durable grants.
`ward request --json --no-prompt` returns `confirmationRequired: true`, a
warning payload, and only `once`/`deny` approval options. The approval command
must include `--confirm-critical`, and `ward run` ignores matching
session/branch/always grants for critical commands.

Ward also scans declared `--action` text because agents show it to users
during approval. Prompt-injection or approval-coercion language forces manual
approval and removes the `always` scope. Action text that combines secret
references with URLs or network transfer hints becomes a critical finding.

## Local files

Project-local:

```txt
.env                  # Ward locked marker by default; plaintext only after ward env unlock
.ward.json
.env.vault
.env.example
AGENTS.md or CLAUDE.md
```

`ward setup` creates or updates these files, imports `.env` into
`.env.vault`, replaces plaintext `.env` with an Ward locked marker file,
registers the project, updates `.gitignore`, and writes `dev` and `migrate`
profiles into `.ward.json`. If `CLAUDE.md` already exists, Ward appends
the agent instructions there; otherwise it uses `AGENTS.md`.

Profile entries are explicit. Agents can request a profile name without seeing
the vault contents, and Ward expands the command and exact env names locally:

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

New `.ward.json` files generate profiles only. They can still contain
`presets` if you add advanced raw-command policy rules later. Profiles are the
user/agent-facing shortcut layer for commands like `ward dev`,
`ward migrate`, and `ward run --profile dev`.
Generated profiles include only env names verified in `.env.vault`; Ward
does not add compatibility guesses such as `DATABASE_URL` when the vault only
contains `DATABASE_URI`. Profile env lists are also treated as the normal scope
declaration, so routine profile requests do not emit `env.scope_deviation`.

Global:

```txt
~/.ward/registry.json
~/.ward/logs/
~/.ward/sessions/
~/.ward/requests/
~/.ward/keys/
~/.ward/cache/
~/.ward/run/
~/.ward/worktrees.json
~/.ward/agents.json
```

Ward creates its own state directories with private permissions where the
platform supports them: directories are `0700` and state files are `0600`.
Encrypted audit logs use a local random key stored at
`~/.ward/cache/log-key.json`; the normal log path does not use the OS
Keychain.
Approval private keys are encrypted locally with the project PIN/passphrase.
During `ward unlock`, Ward loads signing capability into broker memory so
later agent subprocesses can request signed approvals without receiving the
vault passphrase or private key.

Trusted worktree roots are configured globally. A new worktree is auto-bound
only when an Ward command is contacted from a path under an allowed root and
Git verification matches the registered project. Weak matches produce a
worktree approval request instead of silently receiving secrets.

## Security boundary

Ward does not stop commands that bypass it:

```bash
cat .env
printenv
pnpm dev
```

The intended workflow is:

```txt
keep .env locked unless explicitly using ward env unlock for manual work
run secret-bearing commands through ward run
view encrypted audit logs through ward logs view with the PIN/passphrase when needed
```

When using `ward run`, put every Ward flag before `--`. Everything after
`--` is treated as the child command:

```bash
# Correct
ward run --agent codex --action "Run dev" --env DATABASE_URL --json --no-prompt -- pnpm dev

# Wrong: --json and --no-prompt are passed to pnpm, not Ward
ward run --agent codex --action "Run dev" --env DATABASE_URL -- pnpm dev --json --no-prompt
```

Automatic worktree env delivery means scoped process env injection through the
broker. It does not write plaintext `.env` files for agents; plaintext `.env`
remains explicit through `ward env unlock`.

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
`WARD_GITHUB_REPO=owner/ward` to install a published release artifact.
