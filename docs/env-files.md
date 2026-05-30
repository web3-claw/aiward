# Env Files

Ward has two different env-file concerns:

1. Ward's own local development settings, used while building this CLI.
2. The target project's dotenv secrets, which Ward imports into `.env.vault`.

Keep those separate. This repository can have a local `.env` for development
knobs, but Ward-managed application secrets belong in the target project that
is being protected.

## Ward Development Env

Use `.env.example` as the template for this repository:

```bash
cp .env.example .env
set -a; . ./.env; set +a
```

Rust does not load `.env` automatically. The export step matters because the
binary reads these values from the process environment.

The main variables are:

| Variable | Purpose |
| --- | --- |
| `WARD_HOME` | Overrides the default `~/.ward` directory for registry, logs, sessions, requests, and local cache files. |
| `WARD_KEYCHAIN` | Optional. Set to `1` to store legacy key-store entries in the OS Keychain instead of the default local `~/.ward/cache/keystore.json` file. Normal run unlock and approval signing use broker memory. |
| `WARD_UNSAFE_TEST_PASSPHRASE` | Test-only PIN/passphrase override that skips the interactive vault prompt. Do not use for real secrets. |
| `WARD_UNSAFE_TEST_APPROVAL` | Test-only approval override. Valid values are `once`, `session`, `branch`, `always`, or `deny`. |
| `WARD_INSTALL_DRY_RUN` | When set to `1`, `install.sh` prints the install target without copying the binary. |
| `WARD_INSTALL_BIN_DIR` | Overrides the install destination used by `install.sh`. Defaults to `$HOME/.local/bin`. |
| `EDITOR` / `VISUAL` | Selects the editor used by `ward edit`. `EDITOR` takes precedence. |

For normal manual testing, keep the prompt bypass variables commented so you can
exercise the real approval and PIN/passphrase flow. Use the unsafe variables
only for isolated tests, demos, and automation.

## Target Project Env

For an application protected by Ward, the starting point is a normal plaintext
dotenv file in that application's repository:

```dotenv
DATABASE_URL=postgres://user:pass@localhost:5432/app
PAYLOAD_SECRET=replace-me
NEXT_PUBLIC_API_URL=http://localhost:3000
```

Run setup from the target project:

```bash
ward init --project my-project
```

`ward init` is the recommended human entry point. When `.env` or
`.env.vault` exists, it runs the full guided setup flow. `ward setup --yes`
remains available for scripts.

The setup flow:

1. Parses the plaintext dotenv file and records the exact env names.
2. Creates or updates `.ward.json`.
3. Generates `dev` and `migrate` profiles from vault-present env names only.
4. Encrypts the plaintext dotenv contents into `.env.vault`.
5. Verifies the vault can decrypt with the chosen PIN/passphrase.
6. Replaces plaintext `.env` with an Ward locked marker file by default.
7. Creates the initial run unlock session unless `--no-unlock` is used.
8. Updates `.gitignore`, creates `.env.example`, writes agent instructions, and registers the project under `WARD_HOME` or `~/.ward`.

After setup, the intended checked-in files are:

```txt
.ward.json
.env.vault
.env.example
AGENTS.md or CLAUDE.md
```

The generated profiles in `.ward.json` store exact env names:

```json
{
  "profiles": {
    "dev": {
      "command": "pnpm dev",
      "env": ["DATABASE_URL", "PAYLOAD_SECRET"],
      "defaultScope": "always",
      "action": "Run local development server"
    }
  }
}
```

If the source env has `DATABASE_URI` but not `DATABASE_URL`, generated profiles
will include `DATABASE_URI` only. Compatibility guesses are not added to
profiles because Ward must not approve env vars that are absent from the
vault.

Profiles are the recommended user and agent entrypoint. New configs omit
`presets` by default, but legacy/custom configs may still include them as
lower-level policy rules for matching raw commands and deciding approval
behavior.

The intended local-only file is:

```txt
.env
```

In the normal protected state, `.env` contains only Ward comments and marker
values. It does not contain plaintext secrets. If you need manual local
development outside Ward, use:

```bash
ward env unlock
pnpm dev
ward env lock
```

Do not commit plaintext `.env` files. `.env.example` should list required names
without real secret values.

## How Commands Get Secrets

Ward is passive. It does not hook the shell or stop commands that bypass it.
Secrets are protected when secret-bearing commands run through `ward run` or a
profile shortcut.

Typical flow:

```bash
ward allow --profile dev --scope always --agent codex
ward dev --agent codex
```

`ward setup` creates the first run unlock session. Use
`ward unlock --ttl 8h` later to refresh it after expiry or after
`ward lock`.

What happens during a run:

1. Ward resolves the project and profile.
2. The requested command and env names are checked against project policy.
3. A matching approval grant is reused or a new approval is requested.
4. The vault is decrypted in memory after an unlock session or PIN/passphrase.
5. Only the approved env names are injected into the child process.
6. Known secret values are redacted from stdout and stderr.
7. Request, approval, execution, session, and alert events are written to encrypted local logs.

The important concept is scoped injection: the child command receives only the
env names that were requested and approved, not the whole vault.

Commands or declared actions that look like secret exfiltration receive a
stricter preflight result. Examples include `printenv`, bare `env`,
`/proc/self/environ`, `process.env`, `os.environ`, direct `echo $SECRET_NAME`,
encoding tools such as `base64`, and clipboard or network tools paired with env
inspection. Suspicious declared action text, such as approval-coercion or
instruction-override language, forces manual approval and removes `always` from
the available scopes. Critical requests cannot use durable grants. Agents must
surface `confirmationRequired: true` to the user and can only record a once-only
approval with `--confirm-critical`.
