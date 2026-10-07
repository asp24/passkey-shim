# 03. A UHID failure surfaces only after the passphrase

## Problem

Since the device is created only after the vault unlocks (commit
"Create the HID device only after the vault is unlocked"), the daemon checks
early only that the broker is reachable and accepted it (`hidbridge.Dial`).
Whether the kernel can actually create the device (`uhid` module loaded,
`/dev/uhid` present) is learned at `dev.Create()` in
`cmd/llavero/daemon.go` (around line 118), after the user typed a passphrase.

This is the price of never showing browsers a locked key. It only hurts on a
misconfigured machine, but then it costs a typed secret per attempt.

## Proposed approach

Let the broker check readiness without creating anything:

1. In `cmd/llavero-uhid`, before listening, open and close `/dev/uhid` once
   (or `stat` it) and refuse to start with a clear journal message if it
   fails. systemd then shows the unit as failed and `Dial` fails before the
   passphrase prompt.
2. Optionally add a `CmdProbe` to the protocol in `internal/hidbridge`: the
   broker opens `/dev/uhid` without `UHID_CREATE2`, closes it and answers
   `Ready` or an error byte. The client calls it right after `Dial`.

Option 1 is enough for the common case (module not loaded at boot) and needs
no protocol change.

## Done when

- With the `uhid` module unloaded, `llavero` fails before asking for a
  passphrase, with a message naming the module.
- A broker test covers the startup check with a fake opener.
