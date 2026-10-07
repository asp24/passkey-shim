# 08. ctaptest writes a real passkey

## Problem

`cmd/ctaptest` registers a credential for the hard-coded RP ID
`example.test` (`const rpID` in `main`). Pointed at the everyday daemon
instead of a throwaway one, it stores a real, permanent passkey for that site
in the user's vault, and each run replaces it. Nothing in the tool or in the
README section that introduces it (README "Testing", around line 260) warns
about this; the README example happens to use a temporary vault, but nothing
enforces it.

## Proposed approach

1. Add a `-rp` flag, defaulting to something unmistakably synthetic such as
   `ctaptest.invalid` (`.invalid` is reserved by RFC 2606 and can never be a
   real origin).
2. Print the RP ID being registered in the first PASS line.
3. In README, state that ctaptest writes to whatever vault the daemon has
   open, and show cleanup: `llavero -forget ctaptest.invalid`.

## Done when

- Running ctaptest twice against a test vault leaves exactly one credential
  for `ctaptest.invalid`, and README tells the reader how to remove it.
