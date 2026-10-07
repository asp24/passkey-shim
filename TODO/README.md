# TODO

Open findings from the broker and package refactor, one per file. Each note
says what is wrong, where, a proposed approach, its trade-offs and how to tell
it is done. Delete a note in the commit that resolves it.

| # | Note | Kind |
|---|------|------|
| 01 | [Graceful daemon shutdown](01-graceful-daemon-shutdown.md) | correctness, needs 02 |
| 02 | [CTAPHID_CANCEL during a prompt](02-ctaphid-cancel-during-prompt.md) | spec compliance |
| 03 | [UHID failure surfaces after the passphrase](03-uhid-failure-after-passphrase.md) | UX trade-off |
| 04 | [Move internal/uhid under the kernel adapter](04-move-uhid-under-kernel-adapter.md) | structure |
| 05 | [Tests for fingerprint, notify and approval](05-tests-for-desktop-integrations.md) | test coverage |
| 06 | [Another user's device is visible to the active seat](06-other-users-device-visible-to-active-seat.md) | security |
| 07 | [Wrap returned errors](07-wrap-returned-errors.md) | error handling |
| 08 | [ctaptest writes a real passkey](08-ctaptest-writes-real-passkey.md) | tooling |

01 and 02 are best done as one change: both need a context threaded into the
approval prompt and the fingerprint scan.
