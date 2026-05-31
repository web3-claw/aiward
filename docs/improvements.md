# Ward Improvement Backlog

These items are intentionally not part of the current repair pass. They should
be implemented after the core behavior is stable.

## Locked `.env` Overwrite Hardening

Make locked `.env` files hard to overwrite accidentally:

- After Ward writes the locked marker, set the file read-only.
- On macOS, apply `chflags uchg` to the locked marker.
- Before `ward env unlock`, `ward env lock`, setup, import, rotate, or teardown
  writes `.env`, clear the flag with `chflags nouchg`.
- Re-apply protection only when `.env` is returned to the locked marker state.

This mitigates editor undo buffers that still contain plaintext dotenv contents.

## Human Session Process Cleanup

Tie human-mode child processes to the guardian lifecycle:

- Track commands launched through human-mode `ward run -- <command>`.
- Run each child in a process group that Ward can terminate as a unit.
- When TTL expires, `ward lock` runs, the guardian receives shutdown, or the
  main shell PID disappears, terminate active human-mode child process groups.
- Stop the web dashboard with the guardian so ports like `7777` do not stay
  open after the session ends.
- Clean stale guardian sockets, ready markers, broker sessions, and dashboard
  listeners during `ward human`, `ward lock`, and broker startup.

This prevents orphaned dev servers and dashboard listeners from previous human
mode sessions.
