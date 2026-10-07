package main

import "testing"

// Chrome's ".dummy" sentinel registration must never reach the vault, and real
// RP IDs must never be caught by the same screen.
func TestRPIDPlausibility(t *testing.T) {
	reject := []string{"", ".", ".dummy", "example.com.", "a..b", "has space.com", "http://x.com", "a/b"}
	accept := []string{"localhost", "dash.cloudflare.com", "webauthn.io", "example.com", "a.b.c.d.example.co.uk"}

	for _, id := range reject {
		if isPlausibleRPID(id) {
			t.Errorf("accepted implausible RP ID %q", id)
		}
	}
	for _, id := range accept {
		if !isPlausibleRPID(id) {
			t.Errorf("rejected real RP ID %q", id)
		}
	}
}
