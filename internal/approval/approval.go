// Package approval asks the user to approve an operation. Every credential
// creation and every assertion goes through here, so that a compromised
// browser tab cannot silently mint or use a passkey.
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

// Menu drives Omarchy's native picker, so the dialog matches the rest of the
// desktop instead of introducing another toolkit.
type Menu struct {
	binary string
}

// NewMenu finds the picker and checks that a display is available to show it.
func NewMenu() (*Menu, error) {
	path, err := exec.LookPath("omarchy-menu-select")
	if err != nil {
		return nil, errors.New("omarchy-menu-select not found on PATH")
	}
	// Without a display the picker cannot appear, and every request would be
	// refused with no visible reason. Catch that here rather than letting it
	// look like the user declining over and over.
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		return nil, errors.New("no WAYLAND_DISPLAY or DISPLAY in the environment, so no prompt could be shown")
	}
	return &Menu{binary: path}, nil
}

// Confirm shows title with choices and blocks until the user picks one. An
// empty choice means the user dismissed the prompt; an error means the prompt
// could not be shown at all.
func (m *Menu) Confirm(title string, choices []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), approvalTimeout)
	defer cancel()

	args := append([]string{title}, choices...)
	cmd := exec.CommandContext(ctx, m.binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("timed out waiting for approval")
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// A non-zero exit means either "dismissed with Escape" or "could
			// not launch". Those must not be conflated: the first is a
			// decision, the second is a broken prompt that would silently
			// refuse every request. Anything on stderr means the latter.
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return "", fmt.Errorf("approval prompt failed to run: %s", msg)
			}
			return "", nil
		}
		return "", err
	}
	// Options may carry a tab-separated subtext; the label is the first field.
	choice := strings.TrimSpace(string(out))
	if i := strings.IndexByte(choice, '\t'); i >= 0 {
		choice = choice[:i]
	}
	return choice, nil
}

// Auto approves everything by picking the first choice. Intended for headless
// testing only; the daemon selects it only behind an explicit flag.
type Auto struct{}

// Confirm returns the first choice without asking anyone.
func (Auto) Confirm(title string, choices []string) (string, error) {
	return choices[0], nil
}
