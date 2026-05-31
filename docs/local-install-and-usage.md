# Install and Usage

This guide explains how to install Ward and test it on your machine.

## Install from crates.io

The easiest way to install is from [crates.io](https://crates.io/crates/aiward):

```bash
cargo install aiward
```

This installs the `ward` binary to `~/.cargo/bin/ward`. Make sure `~/.cargo/bin`
is on your `PATH`:

```bash
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

## Prerequisites

Install Rust with Cargo if needed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

## Verify the Source Checkout

Clone the repository and verify:

```bash
git clone https://github.com/aiWardsh/aiward
cd aiward
cargo fmt --check
cargo check
cargo test -- --test-threads=1
```

## Run Without Installing

```bash
cargo run -- --help
cargo run -- init --project demo
```

## Safe Demo Flow

Use a temporary folder first so you do not touch a real project:

```bash
mkdir -p /tmp/ward-demo
cd /tmp/ward-demo

cat > .env <<'EOF'
DATABASE_URL=postgres://user:pass@localhost:5432/demo
PAYLOAD_SECRET=fake-payload-secret
NEXT_PUBLIC_API_URL=http://localhost:3000
EOF
```

Run guided init:

```bash
ward init --project demo
```

Ward will:
- Create `.ward.json` with your project config and a random vault nonce
- Import `.env` into an encrypted vault file with a derived filename
- Verify the vault can decrypt
- Replace plaintext `.env` with a locked marker
- Create the initial run unlock session (session-encrypts the vault)
- Register the project globally
- Update `.gitignore` to include `.env`, `.env.*`, and `.ward.json`
- Write profile-based agent instructions to `AGENTS.md`

The vault has no fixed name — its filename is derived from your passphrase and
a random nonce. You don't need to remember it; ward resolves it automatically.

For non-interactive scripted setup:

```bash
ward setup --yes --project demo
```

Check the setup:

```bash
ward doctor
```

## Create a Recovery Key

After setup, create a recovery key. This lets you restore access if a session
is interrupted and the broker can't restore the vault automatically.

```bash
ward recovery create
```

You'll be prompted for your vault passphrase and a new recovery PIN (minimum
4 characters, any characters). The PIN is independent from your vault passphrase.

Export a backup to a safe location:

```bash
ward recovery export
```

This defaults to the Desktop. Store the file somewhere separate from your
machine — a USB drive, a secure cloud backup, or a password manager.

`ward doctor` will warn you if the recovery key is missing or no backup has
been exported.

## Session Encryption

While an unlock session is active, the vault on disk is re-encrypted with a
random ephemeral key held only in broker memory. Your passphrase is not needed
to access the vault during the session — the broker handles decryption
transparently.

When you run `ward lock`, the broker restores the vault to passphrase encryption
before stopping.

## Run a Command With Scoped Secrets

```bash
ward run \
  --agent codex \
  --action "Check database URL availability" \
  --env DATABASE_URL \
  -- sh -c 'test -n "$DATABASE_URL"'
```

All Ward flags must be before `--`. Everything after `--` is the child command:

```bash
# Correct
ward run --agent codex --action "Run dev" --env DATABASE_URL --json --no-prompt -- pnpm dev

# Wrong: these flags go to pnpm, not Ward
ward run --agent codex --action "Run dev" --env DATABASE_URL -- pnpm dev --json --no-prompt
```

To reduce prompts for a trusted dev command:

```bash
ward allow --profile dev --scope always --agent codex
ward dev --agent codex
```

## Vault Rotation

Rotate the vault to a new derived filename at any time:

```bash
ward rotate
```

This generates a new random nonce, re-encrypts the vault at the new path,
removes the old file, and updates `.ward.json`. Use this after any suspected
filename exposure or as part of regular key hygiene.

## Human Mode

Human mode turns your terminal into a ward-protected session. Secret-bearing
commands go through ward automatically.

```bash
ward human
```

Add this to your shell config for automatic integration:

```bash
eval "$(ward shell-init)"
```

Lock when done:

```bash
ward lock
```

## Manual Local Development

If you want to run a tool directly without an agent:

```bash
ward env unlock
pnpm dev
ward env lock
```

`ward env lock` re-encrypts `.env.vault`, verifies it can decrypt, and restores
the locked marker.

## Request Access Before Running (Agent Flow)

```bash
ward request \
  --profile dev \
  --agent claude \
  --worktree "$PWD" \
  --git-remote "$(git config --get remote.origin.url)" \
  --commit "$(git rev-parse HEAD)" \
  --branch "$(git branch --show-current)" \
  --json \
  --no-prompt
```

After the user approves:

```bash
ward unlock --ttl 8h
ward approve <request-id> --scope session --agent-mediated --json
```

## Edit the Vault

```bash
ward edit
```

Ward decrypts to a temporary file, opens `$EDITOR` or `$VISUAL`, validates
dotenv syntax, re-encrypts the vault, and removes the temporary file.

## Validate, Lock, and Inspect Logs

```bash
ward unlock --ttl 8h
ward lock

ward logs view executions
ward logs verify
ward logs verify --full
ward logs export executions --output executions.log
```

## Vault and Env Helpers

```bash
ward projects list
ward projects show my-project
ward projects use my-project
ward env list --project my-project
ward env set --project my-project OPENAI_API_KEY=sk-local
ward env unset --project my-project OPENAI_API_KEY
ward env export --project my-project --output .env.export
```

## Multi-Worktree Usage

Register the canonical project once:

```bash
cd /path/to/main/project
ward register my-project
```

From a worktree or temporary clone:

```bash
ward use my-project
ward run --profile migrate --agent codex --branch feature/migration
```

## Reset Local Test State

```bash
rm -rf /tmp/ward-demo    # delete demo project
rm -rf ~/.ward           # delete all ward state (registry, grants, logs, recovery)
```

To remove Ward from one project while preserving logs:

```bash
ward teardown --yes
```

## Important Limits

Ward does not protect secrets if you bypass it:

```bash
cat .env
printenv
pnpm dev
```

The intended workflow is:

1. Encrypt `.env` into the vault during setup.
2. Keep `.env` locked unless you explicitly run `ward env unlock`.
3. Run secret-bearing commands through `ward run`.
4. Create a recovery key and export a backup.
5. Review encrypted logs through PIN-gated `ward logs view` when needed.

Ward is not anti-malware. A same-user process can still delete local files if
the OS allows it. Encrypted hash-chained logs provide confidentiality and tamper
evidence, not undeletable audit storage.
