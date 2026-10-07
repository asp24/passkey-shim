// Package approval asks the user to approve an operation. Every credential
// creation and every assertion goes through here, so that a compromised
// browser tab cannot silently mint or use a passkey.
//
// The prompt is drawn by an external program native to the desktop, so the
// dialog matches the rest of the session instead of pulling a GUI toolkit
// into the daemon. Each backend wraps one such program.
package approval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// approvalTimeout is deliberately shorter than the browser's own WebAuthn
// timeout, so a user who walks away gets a clean decline rather than a hung
// dialog the browser has already given up on.
const approvalTimeout = 45 * time.Second

// Backend names accepted by New.
const (
	BackendAuto    = "auto"
	BackendOmarchy = "omarchy"
	BackendZenity  = "zenity"
)

// Prompt asks the user to pick one of several choices. It has the shape of
// ctap.Approver.
type Prompt interface {
	Confirm(ctx context.Context, title string, choices []string) (string, error)
}

// New returns the prompt for backend. BackendAuto prefers Omarchy's picker
// when it is installed, since a user who has it wants it, and falls back to
// zenity, which ships with GNOME and is packaged everywhere else.
func New(backend string) (Prompt, error) {
	switch backend {
	case BackendOmarchy:
		return NewOmarchy()
	case BackendZenity:
		return NewZenity()
	case BackendAuto:
	default:
		return nil, fmt.Errorf("unknown approval backend %q (want %s, %s or %s)",
			backend, BackendAuto, BackendOmarchy, BackendZenity)
	}

	om, omErr := NewOmarchy()
	if omErr == nil {
		return om, nil
	}
	zen, zenErr := NewZenity()
	if zenErr == nil {
		return zen, nil
	}
	return nil, fmt.Errorf("no approval backend available: %w", errors.Join(omErr, zenErr))
}

// lookup finds a prompt program and checks that a display is available to
// show it.
func lookup(binary string) (string, error) {
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("%s not found on PATH", binary)
	}
	// Without a display the prompt cannot appear, and every request would be
	// refused with no visible reason. Catch that here rather than letting it
	// look like the user declining over and over.
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		return "", errors.New("no WAYLAND_DISPLAY or DISPLAY in the environment, so no prompt could be shown")
	}
	return path, nil
}

// result is what a prompt program left behind once it exited on its own.
type result struct {
	stdout   string
	stderr   string
	exitCode int
}

// runPrompt runs a prompt program until it exits, timeout passes or ctx is
// cancelled. Cancelling ctx kills the program, so the dialog disappears with
// the request. An error means the program never produced a decision; a
// non-zero exit is not an error, because prompts use exit codes to report
// what the user did.
func runPrompt(ctx context.Context, timeout time.Duration, binary string, args ...string) (result, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(waitCtx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return result{}, fmt.Errorf("approval prompt cancelled: %w", ctx.Err())
	}
	if waitCtx.Err() != nil {
		return result{}, errors.New("timed out waiting for approval")
	}
	res := result{
		stdout: strings.TrimSpace(stdout.String()),
		stderr: strings.TrimSpace(stderr.String()),
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.exitCode = ee.ExitCode()
		return res, nil
	}
	if err != nil {
		return result{}, fmt.Errorf("running approval prompt: %w", err)
	}
	return res, nil
}

// Auto approves everything by picking the first choice. Intended for headless
// testing only; the daemon selects it only behind an explicit flag.
type Auto struct{}

// Confirm returns the first choice without asking anyone.
func (Auto) Confirm(_ context.Context, title string, choices []string) (string, error) {
	return choices[0], nil
}
