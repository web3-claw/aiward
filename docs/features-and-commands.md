# EnvGate Features and Command Reference

This document explains what EnvGate does, how the package is expected to work,
and what each command is responsible for.

EnvGate is a local-first, passive AI secret firewall for development machines.
It keeps env secrets encrypted at rest, gives agents scoped access only through
explicit EnvGate commands, and writes encrypted tamper-evident audit logs.

## Security Model

EnvGate is passive. It does not install a daemon, shell hook, filesystem watcher,
PTY wrapper, network monitor, or terminal-wide scanner.

EnvGate protects secrets only when the user or agent follows the EnvGate flow:

```bash
envgate request ...
envgate run ...
envgate dev
envgate migrate
```

Commands that bypass EnvGate are outside the MVP boundary:

```bash
cat .env
printenv
pnpm dev
```

The expected safe behavior is:

```txt
Keep .env locked by default.
Use envgate run/dev/migrate for AI-assisted secret-bearing commands.
Use envgate env unlock only when a human explicitly wants plaintext .env for manual local work.
Use envgate env lock after manual work to re-encrypt and restore the locked .env marker.
Use envgate logs view/export only after PIN/passphrase confirmation.
```

## Package Behavior

EnvGate is distributed as a local CLI binary named `envgate`.

The local installer:

```bash
./install.sh
```

builds the Rust release binary and installs it to:

```txt
~/.local/bin/envgate
```

If `~/.local/bin` is not on `PATH`, the installer prints a short PATH fix.

After the GitHub repository slug is configured, the same script can download a
published release instead:

```bash
ENVGATE_GITHUB_REPO=owner/envgate ./install.sh
ENVGATE_GITHUB_REPO=owner/envgate ENVGATE_VERSION=v0.1.0 ./install.sh
```

Set `ENVGATE_FORCE_LOCAL_BUILD=1` to force a local Cargo build.

EnvGate uses local project files and global user state. It has no backend.

Project-local files:

```txt
.env
.env.vault
.envgate.json
.env.example
AGENTS.md or CLAUDE.md
```

Global user state:

```txt
~/.envgate/
|-- registry.json
|-- logs/
|-- sessions/
|-- requests/
|-- keys/
|-- run/
|-- worktrees.json
|-- agents.json
`-- cache/
```

Private permissions are used where supported:

```txt
directories: 0700
state files: 0600
```

## Core Features

### Encrypted Env Vault

EnvGate stores canonical secrets in `.env.vault`.

The vault is encrypted with:

```txt
Argon2id key derivation
AES-256-GCM encryption
```

The PIN/passphrase is required to decrypt, edit, export, or lock/unlock env
files. A 4-character PIN is accepted as the minimum convenience mode for local
use; use a longer passphrase if `.env.vault` may leave the machine.

### Managed Locked `.env`

After setup or import, EnvGate replaces plaintext `.env` with a safe locked
marker file. The locked `.env` contains no secret values. It explains that AI
agents should use EnvGate commands instead of reading `.env`.

The three `.env` states are:

```txt
locked              safe marker file, no secrets
plaintext-unlocked  temporary manual-development dotenv file
exported            standalone plaintext export, outside normal locked flow
```

### Global Project Registry

EnvGate can manage many local projects from one global registry. This supports
multi-worktree and temporary clone workflows without copying secrets around.

Registry data lives in:

```txt
~/.envgate/registry.json
```

### Profiles

Profiles live in `.envgate.json` and provide short safe commands such as:

```bash
envgate dev
envgate migrate
envgate run --profile dev
```

A profile stores:

```json
{
  "command": "pnpm dev",
  "env": ["DATABASE_URL", "PAYLOAD_SECRET"],
  "defaultScope": "always",
  "action": "Run development server"
}
```

Profile env names are explicit, not wildcards. Agents can request a profile
without seeing vault contents.

### Presets

New `.envgate.json` files do not include presets by default. Presets are still
supported for legacy/custom configs, but they are lower-level policy rules for
raw command matching and approval behavior. Use profiles for normal user and
agent workflows. Use presets only when you need policy matching for commands
that do not have a profile.
Profile env lists are treated as the expected scope for profile-backed
requests; env vars listed in a matched profile do not produce
`env.scope_deviation`.

### Approval Grants

Approval grants authorize a command and env scope. They do not decrypt secrets.

Grant matching requires:

```txt
same project
same command string
requested envs are a subset of approved envs
matching scope rules
agent match when both grant and request specify an agent
```

Scopes:

```txt
once     valid for one immediate use
session  persisted with 8 hour expiry
branch   valid for same project and branch
always   valid for same project
deny     logged as denial, not persisted as an allow grant
```

### On-Demand Broker and Unlock Sessions

Guided `envgate init` and `envgate setup` create the first short-lived run
unlock session by default. `envgate unlock --ttl 8h` refreshes it later after
expiry or after `envgate lock`. Unlock sessions let EnvGate decrypt internally
for approved `envgate run` commands without repeatedly prompting for the vault
PIN/passphrase.

`envgate unlock` starts or refreshes an on-demand local broker. The broker keeps
active vault decrypt capability and session signing capability in memory and
listens on a private Unix socket:

```txt
~/.envgate/run/envgate.sock
```

The broker is not installed as a daemon. It starts only when EnvGate is
contacted, it does not hook the shell, and it does not monitor the filesystem or
terminal input. `~/.envgate/sessions/unlocks.json` is non-sensitive session
metadata; active decrypt material lives in broker memory.

Unlock material is never printed, accepted as a CLI argument, written to project
files, or exposed to agents.

Approval grants and unlock sessions are separate:

```txt
grant           says "this command may use these env names"
unlock session  lets EnvGate decrypt internally for the approved command
```

### Agent Non-Interactive Flow

Codex, Claude Code, and similar tools should use JSON no-prompt commands:

```bash
envgate run --profile dev \
  --agent codex \
  --worktree /absolute/project-or-worktree \
  --git-remote https://example.test/repo.git \
  --commit <sha> \
  --branch feature/example \
  --json \
  --no-prompt
```

In no-prompt mode, EnvGate never opens a TTY prompt.
For repositories with no `origin` remote, pass `--git-remote ""` explicitly.
Omitting `--git-remote` is still treated as missing context.

No-prompt agent calls must always include complete context:

```txt
--agent
--worktree
--branch
--git-remote
--commit
--action
--profile
```

For non-profile commands, replace `--profile` with exact `--command` and exact
`--env` names. EnvGate verifies the claimed worktree, branch, remote, commit,
and canonical path locally before creating approvals, reusing grants, signing
receipts, or executing.

If approval is missing, EnvGate returns JSON with:

```txt
approvalRequired
requestId
approvalOptions
approveCommands
denyCommand
findings
critical confirmation fields when needed
```

Agents should show approval choices with native structured UI when available,
not loose prose. If the response includes `action.*` findings, surface them
before asking for approval; suspicious action text removes `always` from the
available approval scopes.

If approval exists but run unlock is missing, EnvGate returns JSON with:

```txt
unlockRequired: true
unlockCommand: "envgate unlock --ttl 8h"
```

If context is missing or mismatched, EnvGate returns structured JSON such as
`context_required`, `context_mismatch`, or `worktree_approval_required` and does
not execute. Agent-facing mismatch JSON redacts EnvGate's verified value and
returns `actualPresent` plus `actualHash` instead.

### Worktree Orchestration

EnvGate orchestrates worktree access only when an EnvGate command is contacted.
It does not scan directories in the background.

Registered projects can define trusted worktree roots. A contacted worktree is
auto-bound only when:

```txt
the path is under an allowed root
Git remote/branch/commit verification matches the registered project
the command/request supplies full agent context
```

Weak matches create a pending worktree request for human approval. Unknown or
mismatched folders are denied. Automatic env delivery means scoped process
injection by `envgate run`; EnvGate does not write plaintext `.env` into agent
worktrees.

### Critical Exploit Confirmation

EnvGate has deterministic preflight detection for common secret-exfiltration
patterns, including:

```txt
printenv
bare env
set
export -p
/proc/self/environ
process.env
os.environ
$_ENV
direct echo of requested env names
base64, xxd, hexdump, od, openssl enc
pbcopy, curl, wget, nc, telnet when paired with env inspection
```

Critical requests:

```txt
cannot receive session, branch, or always grants
can only be denied or approved once
require --confirm-critical on approval
force fresh approval even if a durable grant exists
```

### Scoped Env Injection

`envgate run` decrypts the vault internally and injects only approved env names
into the child process.

Example:

```bash
envgate run --agent codex --action "Run migration" --env DATABASE_URL -- pnpm payload migrate
```

Only `DATABASE_URL` is injected if approved.

### Output Redaction and Alerts

EnvGate redacts exact injected secret values from child stdout/stderr. It also
logs alerts for output that looks like:

```txt
env dumps
secret-shaped KEY=value output
known high-risk key names
```

The current MVP does not interrupt the child process for output alerts. It
redacts and logs.

### Encrypted Tamper-Evident Logs

Logs are encrypted JSONL envelopes under:

```txt
~/.envgate/logs/
```

Log kinds:

```txt
requests
approvals
executions
alerts
sessions
```

Each log entry includes cleartext verification metadata:

```txt
version
kind
sequence
timestamp
previous hash
nonce
ciphertext
entry hash
```

Payloads are AES-256-GCM encrypted. Hash chains make modification or reordering
detectable. Same-user deletion is not physically prevented; deleted logs should
be treated as a high-severity signal.

### Doctor Checks

`envgate doctor` checks local project health:

```txt
.envgate.json exists and parses
.env.vault exists
project resolves through registry
plaintext .env warnings
locked/stale/missing .env state
.env.* likely-secret warnings, excluding .env.example and .env.vault
.gitignore contains .env and .env.*
registered vault path exists
encrypted alert count
```

### Teardown

`envgate teardown` exports plaintext env, verifies it, removes project-local
EnvGate files, unregisters the project, and removes project-scoped local state.
Encrypted audit logs are preserved by default.

## First-Time Setup

Recommended onboarding:

```bash
./install.sh
envgate init --project my-project
envgate allow --profile dev --scope always --agent codex
envgate dev --agent codex
```

`envgate init` is the human-friendly entry point. If `.env` or `.env.vault`
exists, it performs the boring setup steps:

```txt
creates or updates .envgate.json
imports .env into .env.vault when .env exists
verifies vault decrypt
replaces .env with locked marker by default
creates or updates .env.example
creates or updates AGENTS.md or CLAUDE.md
updates .gitignore
registers the project globally
generates dev and migrate profiles from vault-present env names
creates the initial run unlock session unless --no-unlock is used
logs setup event
```

Use `envgate setup --yes --project my-project` for scriptable onboarding with
the same recommended defaults.

## Command Reference

### `envgate setup`

Initialize, import, register, and create profile-based onboarding in one flow.

```bash
envgate setup --yes --project my-project
```

Options:

```txt
--yes                 use recommended defaults
--project <name>      project name
--source <path>       source dotenv file, default .env
--vault <path>        vault path, default .env.vault
--commit-vault        keep .env.vault commit-friendly through .gitignore
--ignore-vault        add/keep .env.vault ignored
--keep-plaintext      unsafe escape hatch; leave plaintext source unchanged
--remove-plaintext    deprecated; remove source after import
--unlock-ttl <ttl>    initial run unlock TTL, default 8h
--no-unlock           skip initial run unlock creation
```

Default behavior is to encrypt `.env`, verify the vault, then replace `.env`
with the locked marker and create an initial run unlock session.
Generated profiles include only env names verified in `.env.vault`. If a later
manual config edit requests an env var that is absent from the vault,
no-prompt runs return `vault_key_missing`, not `unlock_required`.

### `envgate init`

Run guided human onboarding by default. If `.env` or `.env.vault` exists,
`init` delegates to the recommended setup flow: config, vault import or
validation, locked `.env`, registry, profiles, `.gitignore`, agent docs, and an
initial run unlock session.

```bash
envgate init
envgate init --project my-project
envgate init --bare
envgate init --force
```

Use `--bare` for the old config-only behavior, which creates or updates:

```txt
.envgate.json
.env.example
AGENTS.md or CLAUDE.md
```

### `envgate import`

Encrypt an existing dotenv file into a vault and lock the source env file.

```bash
envgate import .env
envgate import .env --vault .env.vault
```

Responsibilities:

```txt
prompt for PIN/passphrase
validate dotenv syntax
encrypt into .env.vault
verify decrypt
replace source .env with locked marker
log vault import
```

### `envgate register`

Compatibility alias for project registration.

```bash
envgate register my-project
envgate register my-project --path /path/to/project
envgate register my-project --vault /path/to/project/.env.vault
```

Prefer `envgate projects register` for new docs and workflows.

### `envgate use`

Compatibility alias for selecting the active global project.

```bash
envgate use my-project
```

Prefer `envgate projects use`.

## Global Project Commands

### `envgate projects list`

List registered projects.

```bash
envgate projects list
```

Shows project name, path, vault path, and active marker.

### `envgate projects show`

Show a registered project or the project resolved from the current directory.

```bash
envgate projects show
envgate projects show my-project
```

### `envgate projects register`

Register a project globally.

```bash
envgate projects register my-project
envgate projects register my-project --path /path/to/project
envgate projects register my-project --vault /path/to/project/.env.vault
```

### `envgate projects use`

Set the active global project.

```bash
envgate projects use my-project
```

The active project is used when EnvGate cannot resolve a project from local
config, path ancestry, or git remote.

### `envgate projects remove`

Remove a project from the global registry.

```bash
envgate projects remove my-project
```

This removes the registry entry only. It does not delete project files or logs.

## Broker Commands

### `envgate broker status`

Show whether the on-demand broker is reachable, its socket path, pid when
available, and active project sessions.

```bash
envgate broker status
```

### `envgate broker socket-path`

Print the private Unix socket path.

```bash
envgate broker socket-path
```

### `envgate broker stop`

Ask the broker to stop.

```bash
envgate broker stop
```

`envgate lock` also clears broker unlock state and stops the idle broker.

## Worktree Commands

### `envgate worktrees list`

List trusted roots, known worktrees, and pending worktree requests for a project.

```bash
envgate worktrees list --project my-project
```

### `envgate worktrees allow-root`

Allow automatic binding for verified worktrees under a root path.

```bash
envgate worktrees allow-root --project my-project /Users/me/worktrees
```

### `envgate worktrees remove-root`

Remove a trusted root.

```bash
envgate worktrees remove-root --project my-project /Users/me/worktrees
```

### `envgate worktrees approve`

Approve a pending weak worktree match.

```bash
envgate worktrees approve <request-id>
```

### `envgate worktrees deny`

Deny a pending weak worktree match.

```bash
envgate worktrees deny <request-id>
```

## Env Vault Commands

### `envgate env list`

List env names stored in the encrypted vault.

```bash
envgate env list
envgate env list --project my-project
```

Prompts for the vault PIN/passphrase. Values are not printed.

### `envgate env set`

Set or update one encrypted env value.

```bash
envgate env set DATABASE_URL=postgres://local
envgate env set --project my-project STRIPE_SECRET_KEY=sk_test_xxx
```

Responsibilities:

```txt
prompt for PIN/passphrase
decrypt vault in memory
set KEY=value
validate dotenv syntax
re-encrypt vault
refresh locked .env marker
write encrypted audit event
```

### `envgate env unset`

Remove one encrypted env value.

```bash
envgate env unset DATABASE_URL
envgate env unset --project my-project STRIPE_SECRET_KEY
```

The command logs whether the key existed.

### `envgate env unlock`

Write plaintext dotenv contents for manual human local development.

```bash
envgate env unlock
envgate env unlock --project my-project
envgate env unlock --output .env.local
envgate env unlock --force
```

This prompts for the vault PIN/passphrase and writes plaintext with a warning
header. The output file is written with restrictive permissions where supported.

Use this only when a human intentionally wants to run local tools outside
EnvGate.

### `envgate env lock`

Re-encrypt a plaintext dotenv file and restore the locked marker.

```bash
envgate env lock
envgate env lock --source .env.local
envgate env lock --project my-project
```

Responsibilities:

```txt
prompt for PIN/passphrase
parse plaintext dotenv
re-encrypt .env.vault
verify decrypt
rewrite source .env back to locked marker
log encrypted audit event
```

### `envgate env export`

Export plaintext dotenv contents to a separate file.

```bash
envgate env export --output .env.export
envgate env export --project my-project --output /tmp/my-project.env
envgate env export --output .env.export --force
```

Stdout export is intentionally explicit because it can leak secrets:

```bash
envgate env export --unsafe-stdout
```

## Request and Approval Commands

### `envgate request`

Request secret access without running a command.

Interactive example:

```bash
envgate request \
  --agent codex \
  --branch feature/example \
  --action "Run migration" \
  --command "pnpm payload migrate" \
  --env DATABASE_URL \
  --env PAYLOAD_SECRET
```

Agent-facing no-prompt example:

```bash
envgate request --profile dev \
  --agent codex \
  --worktree /repo \
  --git-remote https://example.test/repo.git \
  --commit <sha> \
  --branch feature/example \
  --json \
  --no-prompt
```

No-prompt mode creates a pending request and prints JSON containing approval
commands for the human or agent UI to surface.

### `envgate approve`

Approve a pending request.

```bash
envgate approve <request-id> --scope once
envgate approve <request-id> --scope session --agent-mediated --json
envgate approve <request-id> --scope branch --agent-mediated --json
envgate approve <request-id> --scope always --agent-mediated --json
```

Critical requests require once-only explicit confirmation:

```bash
envgate approve <request-id> --scope once --confirm-critical --agent-mediated --json
```

Critical requests cannot be approved as `session`, `branch`, or `always`.

### `envgate deny`

Deny a pending request.

```bash
envgate deny <request-id>
envgate deny <request-id> --agent-mediated --json
```

Denials are logged but never persisted as allow grants.

### `envgate allow`

Create a durable approval grant directly for known safe commands.

```bash
envgate allow --profile dev --scope always --agent codex
envgate allow --profile migrate --scope branch --agent codex --branch feature/db
envgate allow --scope always --agent codex --command "pnpm dev" --env DATABASE_URL
```

For profiles, the default scope is used when `--scope` is omitted:

```txt
dev      always
migrate  branch
```

For non-profile `--command` usage, `--scope` is required.

`envgate allow` refuses critical commands because it only creates durable
grants.

## Grant Commands

Reusable approval grants are signed. EnvGate creates a per-project Ed25519
approval key, stores the public metadata under `~/.envgate/keys/`, and keeps the
private key encrypted with the project PIN/passphrase. During `envgate unlock`,
signing capability is loaded into broker memory. `envgate approve` and `envgate
allow` ask the broker to create
a receipt for the exact approved project, agent, branch, command hash, env
names, scope, expiry, request id, and critical-confirmation state.

An active broker unlock session is therefore required before creating reusable
approval grants:

```bash
envgate unlock --ttl 8h
envgate approve <request-id> --scope session --agent-mediated --json
envgate allow --profile dev --scope always --agent codex
```

Unsigned legacy grants and edited grants are ignored during reuse. `doctor`
reports invalid or unsigned grants, and `grants list` shows each grant's signed
status and receipt hash.

### `envgate grants list`

List stored approval grants, including signature status.

```bash
envgate grants list
```

### `envgate grants revoke`

Revoke one grant.

```bash
envgate grants revoke <grant-id>
```

### `envgate grants prune`

Remove expired grants.

```bash
envgate grants prune
```

## Run Commands

### `envgate run`

Run a command with scoped secret injection.

Manual command example:

```bash
envgate run \
  --agent codex \
  --action "Run dev server" \
  --env DATABASE_URL \
  -- pnpm dev
```

All EnvGate flags must appear before `--`. Everything after `--` is passed to
the child command:

```bash
# Correct
envgate run --agent codex --action "Run dev" --env DATABASE_URL --json --no-prompt -- pnpm dev

# Wrong: --json and --no-prompt are pnpm arguments here
envgate run --agent codex --action "Run dev" --env DATABASE_URL -- pnpm dev --json --no-prompt
```

Profile example:

```bash
envgate run --profile dev --agent codex
```

Agent-safe no-prompt example:

```bash
envgate run --profile dev \
  --agent codex \
  --worktree /repo \
  --git-remote https://example.test/repo.git \
  --commit <sha> \
  --branch feature/example \
  --json \
  --no-prompt
```

Behavior:

```txt
resolve project
expand profile if provided
evaluate policy and critical findings
check approval grants
in no-prompt mode, return JSON if approval or unlock is missing
write execution.started encrypted log before spawning
decrypt vault internally
inject only approved env names
redact stdout/stderr
write execution.finished and alert logs
return child exit code behavior through EnvGate
```

### `envgate dev`

Shortcut for:

```bash
envgate run --profile dev
```

Examples:

```bash
envgate dev --agent codex
envgate dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/example --json --no-prompt
```

### `envgate migrate`

Shortcut for:

```bash
envgate run --profile migrate
```

Examples:

```bash
envgate migrate --agent codex --branch feature/db
envgate migrate --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/db --json --no-prompt
```

## Vault Session Commands

### `envgate unlock`

Create a short-lived run unlock session.

```bash
envgate unlock
envgate unlock --ttl 8h
envgate unlock --ttl 30m
envgate unlock --ttl 1d
```

Supported TTL suffixes:

```txt
m minutes
h hours
d days
```

This validates the vault PIN/passphrase, loads unlock capability into broker
memory, and lets approved `envgate run` commands decrypt internally until the
TTL expires.

`envgate unlock` is for command execution only. It does not unlock logs view or
edit.

### `envgate lock`

Clear run unlock sessions and revoke session-scoped grants.

```bash
envgate lock
```

It does not remove branch or always grants.

### `envgate edit`

Safely edit the encrypted vault.

```bash
envgate edit
```

Flow:

```txt
prompt for vault PIN/passphrase
decrypt to temporary file with restrictive permissions
open $EDITOR, VISUAL, or nano
validate dotenv syntax after editor exits
re-encrypt .env.vault
remove temporary file
log edit event
```

## Logs Commands

### `envgate logs`

Print encrypted log directory or encrypted log paths.

```bash
envgate logs
envgate logs requests
envgate logs approvals
envgate logs executions
envgate logs alerts
envgate logs sessions
```

This does not decrypt logs.

### `envgate logs view`

Decrypt and print one log kind.

```bash
envgate logs view executions
envgate logs view alerts
```

Always prompts for the vault PIN/passphrase before decrypting. EnvGate prints a
warning that logs are read-only for review, edits are tamper-evident, and
deleted logs are serious.

Encrypted audit log payloads use a random local log key stored at
`~/.envgate/cache/log-key.json` with private file permissions. EnvGate does not
use the OS Keychain for this log key in the normal path.

### `envgate logs export`

Decrypt one log kind and write it to a file.

```bash
envgate logs export executions --output executions.jsonl
envgate logs export alerts --output alerts.jsonl --force
```

Always prompts for the vault PIN/passphrase.

### `envgate logs verify`

Verify encrypted log metadata and hash chains without decrypting payloads.

```bash
envgate logs verify
envgate logs verify executions
```

Use this to detect malformed, modified, or reordered log entries.

### `envgate logs verify --full`

Verify hash chains and decryptability.

```bash
envgate logs verify --full
envgate logs verify executions --full
```

This requires the vault PIN/passphrase.

### `envgate logs unlock`

Deprecated compatibility command.

```bash
envgate logs unlock --ttl 15m
```

It validates the PIN/passphrase but does not enable future log viewing.
`logs view` and `logs export` still prompt every time.

## Maintenance Commands

### `envgate doctor`

Inspect current project health.

```bash
envgate doctor
```

Use this after setup, after moving worktrees, or after manual file changes.

### `envgate teardown`

Export plaintext env, remove EnvGate project-local files, and unregister the
project.

```bash
envgate teardown --yes
envgate teardown --project my-project --yes
envgate teardown --yes --restore-env
```

Teardown:

```txt
exports plaintext dotenv
verifies exported dotenv syntax
removes .envgate.json
removes .env.vault
removes locked .env marker when replaced by exported plaintext
removes EnvGate generated sections from AGENTS.md and CLAUDE.md
unregisters project
removes project-scoped grants
removes project-scoped pending requests
clears project unlock sessions
preserves encrypted audit logs
```

`--yes` is required. By default teardown exports plaintext to `.env.export`.
Use `--restore-env` to explicitly restore plaintext `.env`. Passing
`--export .env` without `--restore-env` fails.

## Recommended Daily Flows

### Human Setup

```bash
./install.sh
envgate init --project my-project
envgate doctor
```

Guided init creates the initial run unlock session by default. Run
`envgate unlock --ttl 8h` later only when that session expires, after
`envgate lock`, or when setup was run with `--no-unlock`.

### AI-Assisted Dev Server

```bash
envgate unlock --ttl 8h
envgate allow --profile dev --scope always --agent codex
envgate dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/example --json --no-prompt
```

### Agent Request First

```bash
envgate request --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/example --json --no-prompt
envgate approve <request-id> --scope always --agent-mediated --json
envgate run --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/example --json --no-prompt
```

### Critical Request

```bash
envgate request \
  --agent codex \
  --worktree /repo \
  --git-remote https://example.test/repo.git \
  --commit <sha> \
  --branch feature/debug \
  --command "sh -c printenv" \
  --env DATABASE_URL \
  --json \
  --no-prompt

envgate approve <request-id> --scope once --confirm-critical --agent-mediated --json
envgate run --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/debug --env DATABASE_URL --json --no-prompt -- sh -c printenv
```

Only use this when the human explicitly expects the command to inspect secrets.

### Manual Local Development

```bash
envgate env unlock
pnpm dev
envgate env lock
```

During the unlocked period, `.env` contains plaintext secrets. Lock it again
before returning to AI-assisted work.

### Review Logs

```bash
envgate logs verify
envgate logs view executions
envgate logs view alerts
```

### Remove EnvGate From One Project

```bash
envgate teardown --yes
```

Encrypted global audit logs remain available for review. The plaintext export is
written to `.env.export`; use `--restore-env` only when you intentionally want
to recreate plaintext `.env`.

## What Agents Should Do

Agents should:

```txt
use envgate request/run/dev/migrate with --json --no-prompt
send full agent, worktree, branch, remote, commit, action, command/profile, and env context every time
surface approval JSON to the user
never ask for or handle vault PIN/passphrases
never auto-approve critical requests
never create durable grants for critical commands
use profiles when available
```

Agents should not:

```txt
read .env directly
ask the user to paste secrets
ask for the vault PIN/passphrase
run secret-bearing commands outside EnvGate
edit encrypted logs or local EnvGate state
```

## What EnvGate Does Not Promise

EnvGate is not:

```txt
anti-malware
kernel sandboxing
enterprise secret management
zero-trust runtime isolation
advanced exfiltration prevention
undeletable audit storage
```

It is a practical local development safety layer for accidental leakage and
AI-assisted workflow visibility.
