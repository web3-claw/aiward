# Ward

Ward is a local-first AI secret firewall. It keeps your environment secrets encrypted at rest and controls when AI agents can access them — without changing how you work.

---

## How it works

Your `.env` file stays encrypted. When you or an AI agent needs to run a command that requires secrets, ward injects only the approved variables into that process — nothing else sees them.

There are two modes:

**Human mode** — you activate ward for your terminal session. Any command you run that needs secrets goes through ward automatically. No flags, no syntax changes.

**Agent mode** — AI agents (Claude, Codex, etc.) request scoped access through ward's approval flow. You see what they're asking for and approve or deny it. Ward generates the agent instructions automatically — you don't configure this manually.

---

## Install

```bash
cargo install aiward
```

Then add `~/.cargo/bin` to your PATH if it isn't already:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

---

## Setup

Run this once inside your project directory:

```bash
cd your-project
ward setup
```

Ward will walk you through encrypting your `.env`, creating a project profile, and wiring up your shell. Your plaintext `.env` is replaced with a locked marker file — secrets live in `.env.vault` from this point on.

---

## Human mode

Human mode turns your current terminal into a ward-protected session. Once active, secret-bearing commands run through ward automatically — no extra flags required.

**Start a session:**

```bash
ward human
```

Ward spawns a guardian tied to your terminal. When you run `pnpm dev`, `node`, or any other command that needs secrets, ward intercepts it, injects the approved env vars, and lets the process run.

**Shell integration** (add to `~/.zshrc` for automatic loading):

```bash
eval "$(ward shell-init)"
```

**Check what's active:**

```bash
ward modes status
```

**Lock your session when done:**

```bash
ward lock
```

---

## Session modes

Modes let you define permission envelopes — which secrets a command is allowed to touch and for how long.

Create a `.ward.modes.json` in your project:

```json
[
  {
    "name": "dev",
    "level": "read",
    "allowedEnv": ["DATABASE_URI", "NEXT_PUBLIC_SERVER_URL"],
    "allowedCommands": ["pnpm dev*"],
    "maxTtl": "8h"
  },
  {
    "name": "database",
    "level": "write",
    "allowedEnv": ["DATABASE_URI", "PAYLOAD_SECRET"],
    "allowedCommands": ["node scripts/*.mjs", "pnpm payload migrate*"],
    "maxTtl": "2h"
  }
]
```

Push modes to your local vault (PIN required):

```bash
ward modes push
```

Unlock with a specific mode:

```bash
ward unlock --ttl 2h --mode dev
```

Now commands outside that mode's `allowedEnv` are blocked automatically — even if you run them manually.

---

## Vault operations

```bash
ward env list                        # see what's stored
ward env set KEY=value               # add or update a secret
ward env unset KEY                   # remove a secret
ward edit                            # open vault in $EDITOR
ward env export --output .env.plain  # write plaintext for manual use
```

---

## Audit logs

Every secret-bearing execution is logged locally, encrypted, and hash-chained:

```bash
ward logs view executions   # see what ran
ward logs view grants       # see what was approved
ward logs verify            # verify log integrity
```

---

## Doctor

```bash
ward doctor
```

Checks your setup: vault, broker, gitignore, grants, and log integrity. Run this if something feels off.

---

## Agent mode

When you run `ward setup`, ward writes an `AGENTS.md` (or appends to `CLAUDE.md`) in your project directory. This file contains everything an AI agent needs to know to work with ward — how to request access, how to run commands, what scope to declare.

You don't need to configure agent mode manually. The file is auto-generated from your profiles and vault contents, and agents pick it up from their context window automatically.

The agent flow at a glance:

```
agent requests access  →  ward evaluates scope  →  you approve or deny
            ↓
  ward injects only the approved env vars into the command
            ↓
  execution is logged with the agent identity, command, and scope
```

Ward detects and blocks suspicious agent behavior before it reaches the approval prompt: full env dumps, secret echoing, network exfiltration patterns, clipboard access, and prompt injection attempts in declared action text.

---

## Security model

Ward protects secrets when commands run through it. It does not prevent a user or process from reading `.env.vault` directly, accessing the keychain, or bypassing ward entirely. The security boundary is explicit opt-in, not OS-level isolation.

What ward guarantees:
- Secrets are never written to disk in plaintext during normal operation
- Every secret injection is logged with the requesting identity and scope
- Approval grants are signed — editing them invalidates them
- Audit logs are hash-chained — tampering is detectable

---

## License

MIT OR Apache-2.0 — free to use, modify, and distribute.
