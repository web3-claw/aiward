# EnvGate Implementation Map

## Product boundary

EnvGate protects against accidental local secret exposure in AI-assisted coding
workflows. It is not a malware sandbox, kernel isolation layer, enterprise vault,
or complete exfiltration prevention system.

The MVP succeeds when plaintext `.env` files are replaced by EnvGate locked
marker files, commands that need secrets run through `envgate run`, and every
secret-bearing execution has an approval and audit trail. This is the passive
version: no shell hooks, no daemon, and no terminal-wide command scanning.

## Core modules

```txt
src/
  cli/          CLI parsing and command dispatch
  config/       Project-local .envgate.json
  env_file/     Locked .env, manual unlock/export, and encrypted env edits
  vault/        .env.vault encryption and decryption
  registry/     ~/.envgate project registry and active project selection
  policy/       Preset matching and scoped env decisions
  approvals/    Interactive and agent-mediated approval decisions
  approval_receipts/ Signed approval receipt keys, payloads, signing, and verification
  grants/       Persisted session, branch, and always approval grants
  pending_requests/ Non-interactive request storage for agent UI approval
  context/      Strict no-prompt agent worktree/branch/remote/commit verification
  agents/       Per-project agent identity records and request proof checks
  worktrees/    Trusted roots, known worktrees, and pending worktree approvals
  broker/       On-demand Unix-socket broker with in-memory unlock capability
  unlock/       Short-lived run/log unlock sessions
  runner/       Scoped env injection, child process execution, output redaction
  detection/    Preflight suspicious-pattern checks
  anomaly/      Passive grant-use anomaly alerts
  logs/         Encrypted hash-chained audit logging
  git_context/  Safe git identity and repository metadata
```

## Main functions

| Area | Function | Responsibility |
| --- | --- | --- |
| CLI | `cli::dispatch` | Route subcommands to domain modules. |
| Config | `ProjectConfig::default_for_dir` | Build initial project config. |
| Config | `default_profiles` | Generate exact-env `dev` and `migrate` profiles from known vault keys. |
| Config | `ensure_gitignore` | Keep plaintext env files ignored and optionally allow committed vaults. |
| Config | `write_project_config` | Persist `.envgate.json`. |
| Vault | `encrypt_env` | Encrypt dotenv plaintext using Argon2id and AES-256-GCM. |
| Vault | `decrypt_env` | Decrypt `.env.vault` into in-memory dotenv text. |
| Vault | `import_env_file` | Read `.env`, encrypt it, and write `.env.vault`. |
| Env file | `lock_env_file` | Replace plaintext `.env` with a safe locked marker. |
| Env file | `unlock_env_file` | Write plaintext `.env` for explicit manual local development. |
| Registry | `register_project` | Add a canonical project and vault path to `~/.envgate/registry.json`. |
| Registry | `resolve_project` | Resolve project by explicit name, local config, active project, or path ancestry. |
| Policy | `evaluate_request` | Match profiles/presets and decide whether approval is required. |
| Approvals | `prompt_for_approval` | Ask allow-once/session/branch/deny in the terminal. |
| Grants | `persist_grant` | Store approved session, branch, and always grants. |
| Approval receipts | `sign_payload` | Sign the canonical approved scope through broker-held signing capability. |
| Approval receipts | `verify_receipt_signature` | Reject edited, unsigned, or malformed approval grants before reuse. |
| Grants | `find_matching_grant` | Reuse only valid signed grants to skip approval prompts while still requiring unlock/PIN/passphrase. |
| Unlock | `create_run_unlock` | Store non-sensitive TTL-bound run unlock metadata. |
| Broker | `unlock_project` | Start or refresh the on-demand broker and load project unlock capability into broker memory. |
| Broker | `execute` | Ask the broker to run approved commands with scoped env injection and redacted output streaming. |
| Context | `verify_no_prompt_context` | Verify agent-provided worktree, branch, remote, commit, and canonical path before no-prompt execution. |
| Worktrees | `evaluate_worktree` | Auto-bind only trusted verified worktrees or create pending worktree approvals. |
| Agents | `ensure_agent` | Create or load per-project agent identity records. |
| Detection | `preflight_findings` | Flag suspicious requested env/command/action combinations, including critical secret-exfiltration patterns. |
| Anomaly | `detect_grant_anomalies` | Emit warning-only grant frequency, outside-hours, and branch-spread alerts. |
| Runner | `run_command` | Decrypt approved env vars, inject them, stream redacted output, and log execution. |
| Logs | `append_event` | Append encrypted hash-chained audit events under `~/.envgate/logs`. |
| Git | `collect_git_context` | Collect safe git metadata for audit logs. |

## User flows

### 1. Small onboarding setup

```txt
User runs envgate init
  -> create .envgate.json
  -> generate dev and migrate profiles with vault-present exact env names
  -> import .env into .env.vault when present
  -> verify decrypt
  -> replace plaintext .env with locked marker by default
  -> register project
  -> update .gitignore
  -> create .env.example and agent instructions
  -> create approval key material and initial run unlock session unless --no-unlock is used
```

`envgate setup --yes` runs the same recommended flow for scripts.

### 2. Import existing .env

```txt
User runs envgate import .env
  -> prompt for vault PIN/passphrase
  -> parse dotenv file
  -> encrypt full env content into .env.vault
  -> replace source .env with locked marker
  -> log vault import
```

### 3. Signed approval grant

```txt
User runs envgate unlock --ttl 8h
  -> decrypt vault to validate PIN/passphrase
  -> start or refresh the on-demand local broker
  -> load active project unlock capability into broker memory
  -> keep approval signing capability in broker memory
  -> write non-sensitive unlock metadata only

User approves request or runs envgate allow
  -> build canonical approval receipt payload
  -> ask broker to sign payload
  -> persist grant plus receipt hash, signer key id, algorithm, and signature

Future envgate run
  -> load candidate grant
  -> verify payload hash, public key signature, expiry, command hash, env subset, scope, branch, and agent
  -> ignore unsigned or modified grants
```

### 3b. Brokered no-prompt agent execution

```txt
Agent runs envgate run --json --no-prompt with full context
  -> require agent, worktree, branch, git remote, commit, action, and command/profile/env data
  -> verify the claimed context with local Git and canonical paths
  -> verify or create an agent identity record
  -> evaluate worktree trust
  -> reuse only signed grants matching the verified context and agent identity
  -> contact the broker over ~/.envgate/run/envgate.sock
  -> broker decrypts only approved env vars in memory
  -> broker spawns the child command and streams redacted output
  -> execution logs include claimed and verified context plus broker session data
```

No-prompt flows never ask follow-up questions interactively. Missing or
mismatched context returns structured JSON and the command does not execute.

### 2b. Manual self-use

```txt
User runs envgate env unlock
  -> prompt for vault PIN/passphrase
  -> decrypt .env.vault
  -> write plaintext .env with warning header and private permissions
User runs envgate env lock
  -> parse current .env
  -> re-encrypt .env.vault
  -> restore locked .env marker
```

### 3. Register project for worktrees

```txt
User runs envgate register ambienta
  -> read .envgate.json
  -> collect git remote and repo root
  -> write ~/.envgate/registry.json
```

### 4. Run a command with scoped env

```txt
Agent/user runs envgate run --env DATABASE_URL -- pnpm dev
  -> resolve project
  -> collect git context
  -> evaluate preset/policy
  -> run preflight detection
  -> bypass durable grants when critical findings are present
  -> prompt for approval when needed
  -> require active broker unlock session or prompt for PIN/passphrase
  -> no-prompt agent runs use broker memory instead of direct unlock file/keychain lookup
  -> write execution.started log before spawning
  -> decrypt vault in memory
  -> inject only DATABASE_URL
  -> spawn child process
  -> redact known secret values from stdout/stderr
  -> write execution.finished log
  -> write warning-only anomaly alerts if grant behavior crosses thresholds
```

When `--json --no-prompt` is used, EnvGate never opens an interactive prompt.
It either executes with an existing grant and active unlock, returns an
approval-required JSON payload, or returns an unlock-required JSON payload.

### 5. Request approval without execution

```txt
Agent runs envgate request ...
  -> resolve project
  -> evaluate policy and detections
  -> reuse matching grant or prompt for approval
  -> persist session/branch/always grant when selected
  -> write request and approval logs
```

Profile-backed requests use the same flow, but the agent only names a profile:

```txt
Agent runs envgate request --profile dev --json --no-prompt
  -> expand command/env/action from .envgate.json
  -> create pending request without exposing vault contents
```

### 5b. Agent-mediated approval

```txt
Agent runs envgate request --json --no-prompt ...
  -> create pending request id under ~/.envgate/requests
  -> return JSON for the agent UI, including findings and critical confirmation text
User approves in agent UI
Agent records envgate approve <request-id> --scope session --agent-mediated --json
  -> create scoped grant without exposing vault keys
```

Critical requests restrict the approval surface:

```txt
Agent sees confirmationRequired=true
  -> show warning title/body to the user
  -> deny by default unless the user explicitly permits the exact command
Agent records envgate approve <request-id> --scope once --confirm-critical --agent-mediated --json
  -> create a one-use approval only
```

### 6. Diagnose project safety

```txt
User runs envgate doctor
  -> check .envgate.json
  -> check .env.vault
  -> check plaintext .env
  -> check .env.* variants except .env.example
  -> check .gitignore coverage
  -> check project registry resolution
  -> report encrypted alert count without decrypting alerts
  -> report actionable warnings
```

### 7. Teardown

```txt
User runs envgate teardown --yes
  -> export plaintext dotenv from the vault to .env.export by default
  -> remove project-local EnvGate config and vault files
  -> unregister the project
  -> remove project-scoped grants, pending requests, and unlock sessions
  -> preserve encrypted audit logs
```

`envgate teardown --yes --restore-env` is the explicit opt-in for restoring
plaintext `.env`.

## Next implementation priorities

1. Refine setup prompts beyond `--yes` for interactive users.
2. Add richer profile templates for common frameworks.
3. Keep the passive boundary explicit in generated agent instructions.
