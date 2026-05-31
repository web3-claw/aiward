# Ward User Flow Infographics

This page is a simple visual explainer for Ward's passive MVP. The diagrams
are written in Mermaid so they render on GitHub and remain easy to edit.

## One Sentence

```txt
Ward encrypts local env secrets, lets agents request only the env names they
need, injects them only into approved commands, and records encrypted audit logs.
```

## Passive Security Boundary

```mermaid
flowchart LR
    A["Developer or AI agent"] --> B{"How is the command run?"}
    B -->|"Plain shell command"| C["Not protected by Ward<br/>Example: pnpm dev"]
    B -->|"ward run or profile shortcut"| D["Protected path"]
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
Ward is not a shell monitor. It protects the explicit Ward path.
```

## Onboarding Flow

```mermaid
flowchart TD
    A["Start with project .env"] --> B["cargo install aiward"]
    B --> C["ward init --project my-app"]
    C --> D["Create .ward.json"]
    C --> E["Encrypt .env into .env.vault"]
    C --> F["Create .env.example"]
    C --> G["Register project in local registry"]
    C --> H["Generate AGENTS.md or CLAUDE.md"]
    C --> I["Replace .env with locked marker"]
    C --> J["Create initial run unlock session"]
    I --> K["ward doctor"]
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
cargo install aiward
ward init --project my-app
ward doctor
```

What to explain:

| Before setup | After setup |
| --- | --- |
| Plain `.env` in the repo | Locked `.env` marker plus encrypted `.env.vault` |
| Manual secret copying | `ward env unlock` / `ward env lock` |
| Agents can accidentally read secrets | Agents get profile commands |
| No local audit trail | Encrypted local logs |
| Manual env copying across worktrees | Registry resolves the project vault |

## Daily Dev Flow

```mermaid
flowchart LR
    A["Start of work day"] --> B["ward unlock --ttl 8h"]
    B --> C["ward allow --profile dev --scope always --agent codex"]
    C --> D["ward dev --agent codex"]
    D --> E["Ward expands dev profile"]
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
ward unlock --ttl 8h
ward allow --profile dev --scope always --agent codex
ward dev --agent codex
```

On the first setup run, the unlock is already created by `ward setup`.
Use `ward unlock --ttl 8h` here after that session expires or after
`ward lock`.

The important point:

```txt
Always allow does not decrypt the vault by itself. It only skips repeated
approval prompts for the same safe command scope.
```

## Profile Shortcut Flow

```mermaid
flowchart LR
    A["Agent asks for profile dev"] --> B[".ward.json"]
    B --> C["Command: pnpm dev"]
    B --> D["Env names: DATABASE_URL, PAYLOAD_SECRET"]
    C --> E["ward run --profile dev"]
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
    participant Ward as Ward CLI
    participant Broker as Local Broker
    participant User as User
    participant Vault as Encrypted Vault

    Agent->>Ward: ward request --profile dev --json --no-prompt plus full context
    Ward-->>Agent: JSON request id, findings, approval options
    Agent->>User: Show requested command and env names
    User-->>Agent: Approve session, branch, always, once, or deny
    Agent->>Ward: ward approve <request-id> --scope session --agent-mediated --json
    Ward-->>Agent: Grant created
    Agent->>Ward: ward run --profile dev --json --no-prompt plus full context
    Ward->>Broker: Send verified command and approved env names
    Broker->>Vault: Decrypt internally from active unlock
    Broker-->>Agent: Run command with scoped env injection
```

Command version:

```bash
ward request --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
ward approve <request-id> --scope session --agent-mediated --json
ward run --profile dev --agent codex --worktree /repo --git-remote https://example.test/repo.git --commit <sha> --branch feature/x --json --no-prompt
```

What the agent must never do:

```txt
Never ask for, store, print, or handle the vault PIN/passphrase.
```

## Brokered Worktree Flow

```mermaid
flowchart TD
    A["ward unlock --ttl 8h"] --> B["Start or refresh local broker"]
    B --> C["Broker keeps unlock/signing capability in memory"]
    D["Agent contacts Ward from worktree"] --> E["Agent sends full context"]
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
Ward detects worktrees only when an Ward command contacts it. It does not
scan folders in the background, and automatic delivery means process env
injection, not writing plaintext .env files.
```

## Critical Exploit Confirmation Flow

```mermaid
flowchart TD
    A["Agent requests a command"] --> B["Ward preflight detection"]
    B --> C{"Critical finding?"}
    C -->|"No"| D["Normal approval options<br/>once, session, branch, always, deny"]
    C -->|"Yes"| E["confirmationRequired: true"]
    E --> F["Agent must show warning to user"]
    F --> G{"User explicitly allows exact command?"}
    G -->|"No"| H["ward deny <request-id> --agent-mediated --json"]
    G -->|"Yes"| I["ward approve <request-id> --scope once --confirm-critical --agent-mediated --json"]
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
ward request \
  --agent codex \
  --action "Debug env" \
  --command "sh -c printenv" \
  --env DATABASE_URL \
  --json \
  --no-prompt

ward deny <request-id> --agent-mediated --json

ward approve <request-id> \
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
    A["Need one command"] --> B["ward run --env DATABASE_URL -- command"]
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
ward run \
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
    H["User wants to inspect logs"] --> J["ward logs view executions"]
    J --> K["Decrypted view in terminal"]
    H --> L["ward logs verify"]
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
ward logs
ward logs view executions
ward logs verify
ward logs verify --full
```

The limitation to explain clearly:

```txt
Logs are encrypted and tamper-evident. They are not undeletable against the same
OS user.
```

## Command Cheat Sheet

| Goal | Command |
| --- | --- |
| Install | `cargo install aiward` |
| One-command onboarding | `ward init --project my-app` |
| Check project safety | `ward doctor` |
| Refresh vault unlock for runs | `ward unlock --ttl 8h` |
| Lock session grants and unlocks | `ward lock` |
| Allow safe dev profile | `ward allow --profile dev --scope always --agent codex` |
| Run dev profile | `ward dev --agent codex` |
| Run migrate profile | `ward migrate --agent codex` |
| Manual plaintext env | `ward env unlock && pnpm dev && ward env lock` |
| List projects | `ward projects list` |
| Set encrypted env | `ward env set KEY=value` |
| Run explicit command | `ward run --env DATABASE_URL -- pnpm dev` |
| Agent creates pending request | `ward request --profile dev --json --no-prompt --agent codex` |
| Approve normal request | `ward approve <request-id> --scope session --agent-mediated --json` |
| Deny request | `ward deny <request-id> --agent-mediated --json` |
| Approve critical request once | `ward approve <request-id> --scope once --confirm-critical --agent-mediated --json` |
| List grants | `ward grants list` |
| Revoke grant | `ward grants revoke <grant-id>` |
| Edit vault | `ward edit` |
| Show log paths | `ward logs` |
| View encrypted logs | `ward logs view executions` |
| Verify log chain | `ward logs verify` |
| Remove Ward from project | `ward teardown --yes` |

## Short Talk Track

Use this when presenting Ward quickly:

1. Setup encrypts `.env` into `.env.vault` and replaces `.env` with a locked marker.
2. Agents use profiles like `ward dev` instead of reading `.env`.
3. Grants reduce approval noise but do not decrypt secrets by themselves.
4. Unlock sessions let Ward decrypt internally for a limited time.
5. Critical commands like `printenv` require a second, once-only confirmation.
6. Every protected secret-bearing action writes encrypted tamper-evident logs.
