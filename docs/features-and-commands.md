# Ward Features and Command Reference

This document explains what Ward does, how the package is expected to work,
and what each command is responsible for.

Ward is a local-first AI secret firewall for development machines. It keeps env
secrets encrypted at rest, gives agents scoped access only through explicit Ward
commands, and writes encrypted tamper-evident audit logs.

## Security Model

Agent mode is passive. Agents must use explicit `ward request`, `ward run`,
`ward dev`, or `ward migrate` flows with scoped env names and full context.

Human mode is the intentional exception. `ward human` may enable shell hooks for
the current terminal so normal developer commands are routed through Ward while
the guardian session is active.

Ward protects secrets only when the user or agent follows the Ward flow:

```bash
ward request ...
ward run ...
ward dev
ward migrate
```

Commands that bypass Ward are outside its protection boundary:

```bash
cat .env
printenv
pnpm dev
```

When human mode is active in that terminal, the shell hook wraps configured
commands and routes them through `ward run -- <command>` automatically.

The expected safe behavior is:

```txt
Keep .env locked by default.
Use ward run/dev/migrate for AI-assisted secret-bearing commands.
Use ward env unlock only when a human explicitly wants plaintext .env for manual local work.
Use ward env lock after manual work to re-encrypt and restore the locked .env marker.
Use ward logs view/export only after PIN/passphrase confirmation.
```

## Package Behavior

Ward is distributed as a CLI binary named `ward`. Install from
[crates.io](https://crates.io/crates/aiward):

```bash
cargo install aiward
```

This installs the binary to `~/.cargo/bin/ward`.

Ward uses local project files and global user state. It has no backend.

Project-local files:

```txt
.env
.ward.json          (vault nonce, profiles, storage mode — gitignored automatically)
.env.example
AGENTS.md or CLAUDE.md
```

Global user state:

```txt
~/.ward/
|-- registry.json
|-- logs/
|-- sessions/
|-- requests/
|-- keys/
|-- run/
|-- recovery/       (recovery key + decoy files)
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

Ward stores canonical secrets in an encrypted vault file. Setup uses
`.env.vault` by default. `ward rotate` can move the vault to a derived hidden
filename based on your passphrase, project name, and a random nonce stored in
`.ward.json`. The rotated filename:

- Looks like random data to anyone who doesn't know your passphrase
- Changes on every `ward rotate`
- Is only reproducible if you know the passphrase

The vault is encrypted with:

```txt
Argon2id key derivation (m=65536, t=3, p=1)
AES-256-GCM encryption
```

The PIN/passphrase is required to decrypt, edit, export, or lock/unlock env files.
A 4-character minimum PIN is accepted for convenience; use a longer passphrase for
higher-value projects.

### Session Encryption

When you run `ward unlock`, the broker does two things:

1. Decrypts the vault with your passphrase to verify it.
2. Immediately re-encrypts the vault with a random ephemeral key held only in broker memory.

While your unlock session is active, the on-disk vault is encrypted with that
ephemeral key — your passphrase-encrypted form does not exist on disk. When you
run `ward lock`, the broker decrypts with the session key and re-encrypts with your
passphrase before shutting down.

If the broker crashes mid-session and the vault remains encrypted with a lost
session key, run `ward recovery restore` with the recovery file and vault
passphrase to rewrite the vault back to passphrase encryption.

### Recovery System

Ward creates a recovery key during setup using the same vault passphrase. There
is no separate recovery PIN prompt.

The recovery directory at `~/.ward/recovery/` contains the real key alongside
a number of decoy files. All files in the directory are the same size and
indistinguishable without the correct passphrase. The real recovery file is identified
by a filename derived from your passphrase — ward finds it automatically.

Recovery commands:

```bash
ward recovery create                # recreate recovery key with the vault passphrase
ward recovery export --output ~/Desktop  # save backup to Desktop
ward recovery import /path/to/file  # restore from external backup
ward recovery restore               # restore the vault from recovery material
```

`ward doctor` warns if the recovery key is missing or no backup has been exported.

### Vault Rotation

`ward rotate` generates a new random nonce, re-encrypts the vault, writes it
to the new derived filename, and removes the old file. This is automatic and
transparent to agents — the new filename is derived from the same passphrase
plus the new nonce.

```bash
ward rotate
```

`.ward.json` is updated with the new nonce and is gitignored automatically on
setup so the nonce never leaks into git history.

### Managed Locked `.env`

After setup or import, Ward replaces plaintext `.env` with a safe locked
marker file. The locked `.env` contains no secret values. It explains that AI
agents should use Ward commands instead of reading `.env`.

The three `.env` states are:

```txt
locked              safe marker file, no secrets
plaintext-unlocked  temporary manual-development dotenv file
exported            standalone plaintext export, outside normal locked flow
```

### Global Project Registry

Ward can manage many local projects from one global registry. This supports
multi-worktree and temporary clone workflows without copying secrets around.

Registry data lives in:

```txt
~/.ward/registry.json
```

### Monorepo and Turborepo Workspaces

Ward detects workspace apps from `pnpm-workspace.yaml`, `package.json`
`workspaces`, and `turbo.json`. From a workspace root, Ward can show every
detected app/package and configure app folders as child Ward projects with
their own `.ward.json`, vault, profiles, registry entry, and logs.

Child project names use `<workspace>:<app>`, for example:

```txt
cms-core:core-workbench
cms-core:creativestudio
```

Workspace discovery never reads plaintext secret values. It reads package
metadata, env file presence, and env names from `.env.example`. Apps with a
real `.env` can be configured immediately. Apps with only `.env.example` are
reported as `needsEnv` until real local env values exist.

### Profiles

Profiles live in `.ward.json` and provide short safe commands such as:

```bash
ward dev
ward migrate
ward run --profile dev
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

New `.ward.json` files do not include presets by default. Presets are still
supported for legacy/custom configs, but they are lower-level policy rules for
raw command matching and approval behavior. Use profiles for normal user and
agent workflows.

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

`ward unlock` starts an on-demand local broker. The broker keeps active vault
decrypt capability and session signing capability in memory and listens on a
private Unix socket:

```txt
~/.ward/run/ward.sock
```

The broker is not installed as a daemon. It starts only when Ward is
contacted. The broker itself does not monitor the filesystem or terminal input;
human-mode shell hooks are installed separately by `ward shell-init` and only
route commands while the guardian session is active.

While the broker is running:
- The vault on disk is session-encrypted (ephemeral key, not your passphrase)
- The original passphrase-encrypted vault is restored when `ward lock` is run
- The ephemeral key exists only in broker memory

Unlock material is never printed, accepted as a CLI argument, written to project
files, or exposed to agents.

### Agent Non-Interactive Flow

Codex, Claude Code, and similar tools should use JSON no-prompt commands:

```bash
ward run --profile dev \
  --agent codex \
  --worktree /absolute/project-or-worktree \
  --git-remote https://example.test/repo.git \
  --commit <sha> \
  --branch feature/example \
  --json \
  --no-prompt
```

In no-prompt mode, Ward never opens a TTY prompt.
For repositories with no `origin` remote, pass `--git-remote ""` explicitly.

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

### Worktree Orchestration

Ward orchestrates worktree access only when a Ward command is contacted.
It does not scan directories in the background.

### Critical Exploit Confirmation

Ward has deterministic preflight detection for common secret-exfiltration
patterns, including:

```txt
printenv / bare env / set / export -p
/proc/self/environ
process.env / os.environ / $_ENV
direct echo of requested env names
base64, xxd, hexdump, od, openssl enc
pbcopy, curl, wget, nc, telnet when paired with env inspection
```

Critical requests:
- Cannot receive session, branch, or always grants
- Can only be denied or approved once
- Require `--confirm-critical` on approval

### Scoped Env Injection

`ward run` decrypts the vault internally and injects only approved env names
into the child process. No other env vars are visible to the child.

### Output Redaction and Alerts

Ward redacts exact injected secret values from child stdout/stderr and logs
alerts for output that looks like env dumps, secret-shaped KEY=value output,
or known high-risk key names.

### Encrypted Tamper-Evident Logs

Log kinds: `requests`, `approvals`, `executions`, `alerts`, `sessions`.

Payloads are AES-256-GCM encrypted. Hash chains make modification or reordering
detectable.

### Doctor Checks

`ward doctor` checks local project health:

```txt
.ward.json exists and parses
vault file exists (at derived path)
project resolves through registry
plaintext .env warnings
locked/stale/missing .env state
.env.* likely-secret warnings
.gitignore contains .env, .env.*, and .ward.json
registered vault path exists
recovery key exists
recovery backup exported
encrypted alert count
```

---

## First-Time Setup

```bash
cargo install aiward
ward setup
ward recovery export
ward doctor
```

`ward setup` imports `.env`, creates profile policy, creates the recovery key,
offers a backup export, registers the project, and creates the initial run
unlock session by default. The initial session-encrypted vault is ready
immediately after setup.

---

## Command Reference

### `ward setup`

Initialize, import, register, and create profile-based onboarding in one flow.

```bash
ward setup --yes --project my-project
ward setup --workspace --all
ward setup --workspace --app core-workbench
```

Options:

```txt
--yes                 use recommended defaults
--project <name>      project name
--source <path>       source dotenv file, default .env
--vault <path>        vault path, default .env.vault
--commit-vault        keep vault commit-friendly through .gitignore
--ignore-vault        add/keep vault ignored
--keep-plaintext      unsafe escape hatch; leave plaintext source unchanged
--remove-plaintext    deprecated; remove source after import
--unlock-ttl <ttl>    initial run unlock TTL, default 8h
--no-unlock           skip initial run unlock creation
--workspace           force workspace/monorepo setup from this root
--app <name>          configure one detected workspace app
--all                 configure all detected workspace apps with .env files
```

With default inputs, `ward setup` auto-detects monorepos and Turborepos and
routes to workspace setup when app folders are found. It prints detected apps,
their env-file status, setup status, and `.env.example` env-name count. Apps
without a plaintext `.env` are skipped instead of creating empty unusable
vaults.

### `ward rotate`

Rotate the vault to a new derived filename. Generates a new random nonce,
re-encrypts the vault at the new path, and removes the old file.

```bash
ward rotate
```

`.ward.json` is updated with the new nonce. Run after any suspected filename
exposure.

### `ward recovery create`

Create a recovery key for this project using the vault passphrase. Generates
the real key and a set of decoy files in `~/.ward/recovery/`. New recovery
keys include encrypted vault material so they can repair a vault left under a
lost broker session key.

```bash
ward recovery create
```

Prompts for the vault passphrase. No separate recovery PIN is created.

### `ward recovery export`

Export the real recovery key to a safe external location.

```bash
ward recovery export
ward recovery export --output /Volumes/USB
```

Defaults to the Desktop if `--output` is omitted. Store the exported file
somewhere separate from your machine (USB drive, secure cloud backup).

### `ward recovery import`

Restore a recovery key backup into `~/.ward/recovery/`.

```bash
ward recovery import /path/to/backup.key
```

### `ward recovery restore`

Restore the current project's vault file from recovery material and return it
to passphrase encryption.

```bash
ward recovery restore
ward recovery restore /path/to/backup.key
```

### `ward init`

Guided human onboarding. If `.env` or `.env.vault` exists, delegates to
the full setup flow.

```bash
ward init
ward init --project my-project
ward init --bare
ward init --force
```

### `ward import`

Encrypt an existing dotenv file into a vault.

```bash
ward import .env
ward import .env --vault .env.vault
```

### `ward unlock`

Create a short-lived run unlock session. Triggers session encryption of the vault.

```bash
ward unlock
ward unlock --ttl 8h
ward unlock --ttl 30m --mode dev
```

### `ward lock`

Restore the vault to passphrase encryption and clear run unlock sessions.

```bash
ward lock
```

### `ward edit`

Safely edit the encrypted vault.

```bash
ward edit
```

### `ward doctor`

Inspect current project health including vault, recovery, gitignore, broker,
dashboard, human mode, grants, and logs.

```bash
ward doctor
```

### `ward dashboard`

Manage the local browser dashboard or open the terminal log dashboard.

```bash
ward dashboard start
ward dashboard start --no-open
ward dashboard status
ward dashboard stop --all
ward dashboard tui
```

The browser dashboard is a standalone localhost service. It shows registered
projects, profile env-name policy, runtime status, and encrypted logs grouped
by project. The overview page manages project/profile policy, while `/logs`
and `/projects/<project>/logs` use the detailed logs layout.

The dashboard never displays or edits secret values. Profile edits manage
profile name, command, action, default scope, and env names only. Adding a
project from the dashboard requires an active unlock/human session; Ward reuses
that broker-held passphrase for setup without sending it to the browser.

### `ward workspace discover`

Discover apps and packages in the current monorepo workspace.

```bash
ward workspace discover
ward workspace discover --json
```

Discovery reports package name, slug, suggested child project name, relative
path, app/package classification, env-file status, setup status, `.env.example`
env names, and package scripts. It does not display plaintext secret values.

### `ward human` and `ward shell-init`

Activate human mode for the current terminal and print shell integration code.

```bash
ward human
ward human --ttl 8h
eval "$(ward shell-init)"
```

When human mode is active, wrapped commands in a Ward project route through
`ward run -- <command>` and receive all vault keys for that human terminal.
If the same wrapped command runs inside a Ward project without an active
guardian for that terminal, the wrapper exits before starting the child command.

### `ward modes list / push / status`

Manage optional session mode envelopes.

```bash
ward modes list
ward modes push
ward modes push --global
ward modes push --project my-project
ward modes status
```

### `ward env list / set / unset / unlock / lock / export`

```bash
ward env list
ward env set DATABASE_URL=postgres://local
ward env unset DATABASE_URL
ward env unlock --output .env
ward env lock --source .env
ward env export --output .env.export
```

### `ward run / dev / migrate`

Run a command with scoped secret injection.

```bash
ward run --profile dev --agent codex --json --no-prompt
ward dev --agent codex
ward migrate --agent codex --branch feature/db
```

### `ward request / approve / deny / allow`

```bash
ward request --profile dev --agent codex --json --no-prompt
ward approve <id> --scope always --agent-mediated --json
ward deny <id> --agent-mediated --json
ward allow --profile dev --scope always --agent codex
```

### `ward grants list / revoke / prune`

```bash
ward grants list
ward grants revoke <grant-id>
ward grants prune
```

### `ward logs view / verify / export`

```bash
ward logs view executions
ward logs unlock --ttl 15m
ward logs verify
ward logs verify --full
ward logs export executions --output executions.jsonl
```

### `ward broker status / stop / socket-path`

```bash
ward broker status
ward broker stop
ward broker socket-path
```

### `ward projects list / show / register / use / remove`

```bash
ward projects list
ward projects show my-project
ward projects register my-project
ward projects use my-project
ward projects remove my-project
```

### `ward worktrees list / allow-root / remove-root / approve / deny`

```bash
ward worktrees list --project my-project
ward worktrees allow-root --project my-project /Users/me/worktrees
ward worktrees approve <id>
ward worktrees deny <id>
```

### `ward teardown`

Export plaintext env, remove Ward project-local files, and unregister.

```bash
ward teardown --yes
ward teardown --yes --restore-env
```

---

## What Agents Should Do

Agents should:

```txt
use ward request/run/dev/migrate with --json --no-prompt
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
run secret-bearing commands outside Ward
edit encrypted logs or local Ward state
```

## What Ward Does Not Promise

Ward is not:

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
