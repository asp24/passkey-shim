# 06. Another user's device is visible to the active seat

## Problem

systemd's `60-fido-id.rules` tags every FIDO hidraw node with `uaccess`,
which grants the user of the *active* seat session access to it. On a
machine where two users are logged in (fast user switching), user B's browser
can open user A's llavero hidraw node and send it CTAP requests.

What still protects A:

- every makeCredential/getAssertion needs A's approval prompt and A's
  fingerprint, and the prompt appears in A's session, not B's;
- A's vault and keys never leave A's daemon.

What B can still do:

- raise approval prompts or fingerprint requests in A's session at will
  (annoyance, and a phishing angle if A approves without reading);
- learn which sites A has passkeys for through `getAssertion`
  `NO_CREDENTIALS` versus a prompt appearing (timing and behaviour oracle).

This is not a regression: before the broker, A's daemon created the same
device. The broker makes a fix possible because it runs as root and knows
which UID it serves.

## Proposed approach

Create the device only while the owner's session is the active one on its
seat, and destroy it otherwise:

1. In the broker, watch logind (`org.freedesktop.login1`) for the sessions of
   `Server.UID`, specifically the `Active` property of the seat session.
2. When it turns inactive, close the kernel device (the client stays
   connected) and send a new lifecycle event so the daemon logs it. When it
   turns active again, recreate the device.
3. Alternatively, as a cheaper first step, have the daemon refuse requests
   (return `OPERATION_DENIED` without prompting) while its own session is
   inactive, using `loginctl show-session $XDG_SESSION_ID -p Active`.

## Trade-offs

- Option 1 needs a D-Bus dependency in the root broker and a protocol
  addition (device-paused/resumed events), so it enlarges the trusted part.
- Option 3 keeps the broker small but still exposes the device node; it only
  stops prompts from appearing.

## Done when

- With two logged-in users and B active, B's browser cannot raise a prompt in
  A's session.
- The chosen behaviour is documented in README's security section.
