# 01. Graceful daemon shutdown

## Problem

`cmd/llavero/daemon.go` handles SIGINT/SIGTERM in a goroutine that closes the
broker connection and calls `os.Exit(0)` (around line 124-130). Deferred
cleanup in `run` never executes, and the goroutine is not tied to any context.
This contradicts the project's concurrency rules (context propagation, no
untracked goroutines).

It has not been replaced with `signal.NotifyContext` on purpose: the main loop
blocks inside `ctaphid.Transport.HandlePacket` while a request waits for the
user, and that wait cannot be interrupted today. A context-based shutdown
would wait for the approval prompt (`approval.approvalTimeout`, 45 s) or the
fingerprint scan (`fingerprint.fingerprintTimeout`, 35 s) before exiting.

## Proposed approach

1. Create the root context with `signal.NotifyContext` in `app.run`.
2. Thread `ctx` through the waits that can block (see 02):
   `ctap.Approver.Confirm(ctx, ...)`, `ctap.UserVerifier.Verify(ctx, ...)`,
   `ctap.Authenticator.Handle(ctx, ...)`, `ctaphid.Transport.HandlePacket`.
3. `approval.Menu.Confirm` already uses `exec.CommandContext`; derive its
   timeout from the passed context instead of `context.Background()`.
4. `fingerprint.Verifier.Verify` must stop on `ctx.Done()` in its select loop
   and still run its deferred `VerifyStop`/`Release`.
5. `context.AfterFunc(ctx, dev.Close)` wakes `dev.Read`; when the loop sees an
   error and `ctx.Err() != nil`, return nil.
6. Delete the signal goroutine and the `os.Exit(0)`.

## Trade-offs

- An interface change in `ctap` touches every fake in
  `internal/ctap/handlers_test.go`.
- A cancelled prompt must answer the host with `statusKeepaliveCancel` (0x2D)
  or the CTAPHID error expected by the spec, not "user declined".

## Done when

- `systemctl --user stop llavero` exits within about a second even with an
  approval prompt or fingerprint scan open, and the prompt disappears.
- The daemon has no `os.Exit` outside `main`.
- A test cancels the context while a fake approver blocks, and `Handle`
  returns promptly with the cancel status.
