<!-- ward-agent-instructions -->
# Ward Secret Access

This repository uses Ward for local secret access. Do not read, print, copy,
or modify plaintext `.env` files. Request only the env vars needed for the
declared command.

Project: ward

Use profiles where available:

```bash
ward request --profile dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward run --profile dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward dev --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
ward migrate --agent <agent-name> --worktree <absolute-path> --git-remote <remote-url-or-empty> --commit <sha> --branch <branch> --json --no-prompt
```

Profiles are the user-facing command layer. They map a short name such as
`dev` or `migrate` to one command and exact env names. Presets may be added to
`.ward.json` as lower-level policy rules for raw command matching and
approval behavior; prefer profiles unless a profile does not exist.

Agent runs outside human mode must identify themselves with `--agent
<agent-name>`. Ward rejects anonymous `run`, `request`, and `allow` calls so
logs and grants stay tied to an agent identity.

No-prompt agent calls must always send full context up front: `--agent`,
`--worktree`, `--branch`, `--git-remote`, `--commit`, `--action`, and either
`--profile` or an exact `--command` plus exact `--env` names. Do not wait for
Ward to ask follow-up questions. Ward verifies the claimed branch, remote,
commit, and worktree path locally before creating or reusing approvals.
For repositories with no `origin` remote, pass `--git-remote ""` explicitly.

Manual request template:

```bash
ward request \
  --agent <agent-name> \
  --worktree <absolute-path> \
  --branch <branch-name> \
  --git-remote <remote-url-or-empty> \
  --commit <sha> \
  --action "<why this command needs secrets>" \
  --command "<exact command to run>" \
  --env <ENV_NAME> \
  --json \
  --no-prompt
```

If a no-prompt command returns `"approvalRequired": true`, show
`approvalOptions`, `approveCommands`, `denyCommand`, and all `findings` to the
user as explicit choices. Use native structured choice UI when your agent
interface supports it; do not present approval choices as loose prose when
buttons, selectors, or typed choice prompts are available. If your structured
choice UI has a 4-option limit, present the approval scopes in the picker and
show `denyCommand` as a separate explicit denial action.

Surface `action.*` findings before asking for approval. They mean the declared
action text may include prompt-injection, approval-coercion, or secret-exposure
language.

After the user approves in the agent UI, record that approval with the matching
approve command:

```bash
ward unlock --ttl 8h
ward approve <request-id> --scope <session|branch|always> --agent-mediated --json
```

Approvals are signed. If `ward approve` or `ward allow` reports
`"status": "unlock_required"` or `signing_key_unavailable`, ask the user to run
`ward unlock --ttl 8h` and then retry the approval. Never ask the user for
the PIN/passphrase directly.

If a no-prompt command returns `"unlockRequired": true`, ask the user to run:

```bash
ward unlock --ttl 8h
```

This usually means the init/setup-created unlock expired, setup was run with
`--no-unlock`, or the user explicitly ran `ward lock`.

If a no-prompt command returns `"status": "vault_key_missing"`, do not ask the
user to unlock again. The broker is already reachable, but the approved profile
or command requested an env var that is not present in `.env.vault`. Surface
`missingEnv` and ask the user to update `.ward.json` or run `ward env
unlock`, add the missing key, then run `ward env lock`.

If the JSON response contains `"confirmationRequired": true`, show the
`confirmation.title`, `confirmation.body`, and recommended action to the user.
Do not rewrite, summarize away, or hide the critical confirmation text. Do not
auto-approve it and do not create a durable grant. Critical requests can only be
denied or approved once:

```bash
ward deny <request-id> --agent-mediated --json
ward approve <request-id> --scope once --confirm-critical --agent-mediated --json
```

Run template:

```bash
ward run \
  --agent <agent-name> \
  --worktree <absolute-path> \
  --branch <branch-name> \
  --git-remote <remote-url-or-empty> \
  --commit <sha> \
  --action "<why this command needs secrets>" \
  --env <ENV_NAME> \
  --json \
  --no-prompt \
  -- <command> <args>
```

All Ward flags must appear before `--`. Everything after `--` is the child
command and its arguments, so do not put `--json`, `--no-prompt`, `--agent`, or
other Ward flags after `--`.

Ward is passive: commands that need secrets must be run through
`ward run`. Automatic worktree delivery means Ward injects scoped
environment variables into the approved child process. It does not write
plaintext `.env` files for agents.

Never ask for, echo, store, or pipe the Ward vault PIN/passphrase.
`ward init` and `ward setup` create the initial run unlock by default; the
user may run `ward unlock --ttl 8h` locally later to refresh it. Viewing
decrypted logs always requires the user's PIN/passphrase. Agent-mediated
approvals are logged trust events, not cryptographic proof of human approval.
