# EnvGate User Flow Infographics

This page is a simple visual explainer for EnvGate's passive MVP. The diagrams
are written in Mermaid so they render on GitHub and remain easy to edit.

## One Sentence

```txt
EnvGate encrypts local env secrets, lets agents request only the env names they
need, injects them only into approved commands, and records encrypted audit logs.
```

## Passive Security Boundary

```mermaid
flowchart LR
    A["Developer or AI agent"] --> B{"How is the command run?"}
    B -->|"Plain shell command"| C["Not protected by EnvGate<br/>Example: pnpm dev"]
    B -->|"envgate run or profile shortcut"| D["Protected path"]
    D --> E["Policy and exploit checks"]
    E --> F["Approval or matching grant"]
    F --> G["Unlock session or PIN/passphrase"]
    G --> H["Scoped env injection"]
    H --> I["Redacted output and encrypted logs"]

    classDef danger fill:#fee2e2,stroke:#b91c1c,color:#111827;
    classDef safe fill:#dcfce7,stroke:#15803d,color:#111827;
    classDef neutral fill:#eef2ff,stroke:#4338ca,color:#111827;
    class C danger;
    class D,E,F,G,H,I safe;
    class A,B neutral;
```

Use this when explaining the product boundary:

```txt
EnvGate is not a shell monitor. It protects the explicit EnvGate path.
```

## Onboarding Flow

```mermaid
flowchart TD
    A["Start with project .env"] --> B["./install.sh"]
    B --> C["envgate init --project my-app"]
    C --> D["Create .envgate.json"]
    C --> E["Encrypt .env into .env.vault"]
    C --> F["Create .env.example"]
    C --> G["Register project in local registry"]
    C --> H["Generate AGENTS.md or CLAUDE.md"]
    C --> I["Replace .env with locked marker"]
    C --> J["Create initial run unlock session"]
    I --> K["envgate doctor"]
    J --> K
    K --> L["Ready for agent-safe local development"]

    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    classDef file fill:#fef3c7,stroke:#b45309,color:#111827;
    classDef done fill:#dcfce7,stroke:#15803d,color:#111827;
    class B,C,J,K command;
    class D,E,F,G,H,I file;
    class L done;
```

Command version:

```bash
./install.sh
envgate init --project my-app
envgate doctor
```

What to explain:

| Before setup | After setup |
| --- | --- |
| Plain `.env` in the repo | Locked `.env` marker plus encrypted `.env.vault` |
| Manual secret copying | `envgate env unlock` / `envgate env lock` |
| Agents can accidentally read secrets | Agents get profile commands |
| No local audit trail | Encrypted local logs |
| Manual env copying across worktrees | Registry resolves the project vault |

## Daily Dev Flow

```mermaid
flowchart LR
    A["Start of work day"] --> B["envgate unlock --ttl 8h"]
    B --> C["envgate allow --profile dev --scope always --agent codex"]
    C --> D["envgate dev --agent codex"]
    D --> E["EnvGate expands dev profile"]
    E --> F["Inject only approved env names"]
    F --> G["Run dev server"]
    G --> H["Write encrypted execution log"]

    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    classDef internal fill:#f3e8ff,stroke:#7e22ce,color:#111827;
    classDef output fill:#dcfce7,stroke:#15803d,color:#111827;
    class B,C,D command;
    class E,F,H internal;
    class G output;
```

Command version:

```bash
envgate unlock --ttl 8h
envgate allow --profile dev --scope always --agent codex
envgate dev --agent codex
```

On the first setup run, the unlock is already created by `envgate setup`.
Use `envgate unlock --ttl 8h` here after that session expires or after
`envgate lock`.

The important point:

```txt
Always allow does not decrypt the vault by itself. It only skips repeated
approval prompts for the same safe command scope.
```

## Profile Shortcut Flow

```mermaid
flowchart LR
    A["Agent asks for profile dev"] --> B[".envgate.json"]
    B --> C["Command: pnpm dev"]
    B --> D["Env names: DATABASE_URL, PAYLOAD_SECRET"]
    C --> E["envgate run --profile dev"]
    D --> E
    E --> F["Grant check"]
    F --> G["Unlock check"]
    G --> H["Run command with scoped env"]

    classDef profile fill:#fef3c7,stroke:#b45309,color:#111827;
    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    classDef protected fill:#dcfce7,stroke:#15803d,color:#111827;
    class B,C,D profile;
    class E,F,G command;
    class H protected;
```

Why profiles matter:

```txt
The agent can ask for "dev" without reading decrypted vault contents.
```

## Agent-Mediated Request Flow

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant EnvGate as EnvGate CLI
    participant Broker as Local Broker
    participant User as User
    participant Vault as Encrypted Vault

    Agent->>EnvGate: envgate request --profile dev --json --no-prompt plus full context
    EnvGate-->>Agent: JSON request id, findings, approval options
    Agent->>User: Show requested command and env names
    User-->>Agent: Approve session, branch, always, once, or deny
    Agent->>EnvGate: envgate approve <request-id> --scope session --agent-mediated --json
    EnvGate-->>Agent: Grant created
    Agent->>EnvGate: envgate run --profile dev --json --no-prompt plus full context
    EnvGate->>Broker: Send verified command and approved env names
    Broker->>Vault: Decrypt internally from active unlock
    Broker-->>Agent: Run command with scoped env injection
```

Command version:

```bash
envgate request --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
envgate approve <request-id> --scope session --agent-mediated --json
envgate run --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
```

What the agent must never do:

```txt
Never ask for, store, print, or handle the vault PIN/passphrase.
```

## Brokered Worktree Flow

```mermaid
flowchart TD
    A["envgate unlock --ttl 8h"] --> B["Start or refresh local broker"]
    B --> C["Broker keeps unlock/signing capability in memory"]
    D["Agent contacts EnvGate from worktree"] --> E["Agent sends full context"]
    E --> F["Verify path, branch, remote, and commit with local Git"]
    F --> G{"Trusted worktree?"}
    G -->|"Registered root or allowed root match"| H["Reuse matching signed grant or create approval request"]
    G -->|"Weak match"| I["worktree_approval_required JSON"]
    G -->|"Mismatch"| J["Deny"]
    H --> K["Broker injects scoped env into child process"]
    K --> L["Encrypted execution log"]

    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    classDef protected fill:#dcfce7,stroke:#15803d,color:#111827;
    classDef warning fill:#fef3c7,stroke:#b45309,color:#111827;
    classDef danger fill:#fee2e2,stroke:#b91c1c,color:#111827;
    class A,D,E command;
    class B,C,F,H,K,L protected;
    class I warning;
    class J danger;
```

The rule:

```txt
EnvGate detects worktrees only when an EnvGate command contacts it. It does not
scan folders in the background, and automatic delivery means process env
injection, not writing plaintext .env files.
```

## Critical Exploit Confirmation Flow

```mermaid
flowchart TD
    A["Agent requests a command"] --> B["EnvGate preflight detection"]
    B --> C{"Critical finding?"}
    C -->|"No"| D["Normal approval options<br/>once, session, branch, always, deny"]
    C -->|"Yes"| E["confirmationRequired: true"]
    E --> F["Agent must show warning to user"]
    F --> G{"User explicitly allows exact command?"}
    G -->|"No"| H["envgate deny <request-id> --agent-mediated --json"]
    G -->|"Yes"| I["envgate approve <request-id> --scope once --confirm-critical --agent-mediated --json"]
    I --> J["One-use approval only"]
    J --> K["Durable grants are blocked"]

    classDef normal fill:#dcfce7,stroke:#15803d,color:#111827;
    classDef warning fill:#fee2e2,stroke:#b91c1c,color:#111827;
    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    class D normal;
    class E,F,G,J,K warning;
    class H,I command;
```

Critical examples:

| Pattern | Why it is risky |
| --- | --- |
| `printenv` or bare `env` | Dumps many environment variables |
| `echo $DATABASE_URL` | Directly prints a requested secret |
| `process.env` or `os.environ` | Runtime env inspection |
| `base64`, `xxd`, `hexdump`, `openssl enc` | Can transform secrets to bypass simple reading |
| `curl`, `wget`, `nc` with env inspection | Possible network exfiltration |
| `pbcopy` with env inspection | Possible clipboard exfiltration |

Command version:

```bash
envgate request \
  --agent codex \
  --action "Debug env" \
  --command "sh -c printenv" \
  --env DATABASE_URL \
  --json \
  --no-prompt

envgate deny <request-id> --agent-mediated --json

envgate approve <request-id> \
  --scope once \
  --confirm-critical \
  --agent-mediated \
  --json
```

The rule:

```txt
Critical requests can be allowed once. They cannot become session, branch, or
always grants.
```

## Manual One-Off Command Flow

```mermaid
flowchart LR
    A["Need one command"] --> B["envgate run --env DATABASE_URL -- command"]
    B --> C["Preflight checks"]
    C --> D{"Grant exists?"}
    D -->|"Yes"| E["Skip approval prompt"]
    D -->|"No"| F["Ask user approval"]
    E --> G["Require unlock or PIN/passphrase"]
    F --> G
    G --> H["Inject only approved env"]
    H --> I["Run child process"]
    I --> J["Log execution"]

    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    classDef decision fill:#fef3c7,stroke:#b45309,color:#111827;
    classDef protected fill:#dcfce7,stroke:#15803d,color:#111827;
    class B,C,G,H,I,J command;
    class D,E,F decision;
    class H,J protected;
```

Command version:

```bash
envgate run \
  --agent codex \
  --action "Run migration" \
  --env DATABASE_URL \
  --env PAYLOAD_SECRET \
  -- pnpm payload migrate
```

## Logs and Review Flow

```mermaid
flowchart TD
    A["Every protected request/run"] --> B["Encrypted JSONL logs"]
    B --> C["requests"]
    B --> D["approvals"]
    B --> E["executions"]
    B --> F["alerts"]
    B --> G["sessions"]
    H["User wants to inspect logs"] --> J["envgate logs view executions"]
    J --> K["Decrypted view in terminal"]
    H --> L["envgate logs verify"]
    L --> M["Detect modified, malformed, or reordered log entries"]

    classDef log fill:#fef3c7,stroke:#b45309,color:#111827;
    classDef command fill:#dbeafe,stroke:#1d4ed8,color:#111827;
    classDef result fill:#dcfce7,stroke:#15803d,color:#111827;
    class B,C,D,E,F,G log;
    class J,L command;
    class K,M result;
```

Command version:

```bash
envgate logs
envgate logs view executions
envgate logs verify
envgate logs verify --full
```

The limitation to explain clearly:

```txt
Logs are encrypted and tamper-evident. They are not undeletable against the same
OS user.
```

## Command Cheat Sheet

| Goal | Command |
| --- | --- |
| Install locally | `./install.sh` |
| One-command onboarding | `envgate init --project my-app` |
| Check project safety | `envgate doctor` |
| Refresh vault unlock for runs | `envgate unlock --ttl 8h` |
| Lock session grants and unlocks | `envgate lock` |
| Allow safe dev profile | `envgate allow --profile dev --scope always --agent codex` |
| Run dev profile | `envgate dev --agent codex` |
| Run migrate profile | `envgate migrate --agent codex` |
| Manual plaintext env | `envgate env unlock && pnpm dev && envgate env lock` |
| List projects | `envgate projects list` |
| Set encrypted env | `envgate env set KEY=value` |
| Run explicit command | `envgate run --env DATABASE_URL -- pnpm dev` |
| Agent creates pending request | `envgate request --profile dev --json --no-prompt --agent codex` |
| Approve normal request | `envgate approve <request-id> --scope session --agent-mediated --json` |
| Deny request | `envgate deny <request-id> --agent-mediated --json` |
| Approve critical request once | `envgate approve <request-id> --scope once --confirm-critical --agent-mediated --json` |
| List grants | `envgate grants list` |
| Revoke grant | `envgate grants revoke <grant-id>` |
| Edit vault | `envgate edit` |
| Show log paths | `envgate logs` |
| View encrypted logs | `envgate logs view executions` |
| Verify log chain | `envgate logs verify` |
| Remove EnvGate from project | `envgate teardown --yes` |

## Short Talk Track

Use this when presenting EnvGate quickly:

1. Setup encrypts `.env` into `.env.vault` and replaces `.env` with a locked marker.
2. Agents use profiles like `envgate dev` instead of reading `.env`.
3. Grants reduce approval noise but do not decrypt secrets by themselves.
4. Unlock sessions let EnvGate decrypt internally for a limited time.
5. Critical commands like `printenv` require a second, once-only confirmation.
6. Every protected secret-bearing action writes encrypted tamper-evident logs.
