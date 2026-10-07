package approval

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Omarchy drives Omarchy's native picker, omarchy-menu-select.
type Omarchy struct {
	binary  string
	timeout time.Duration
}

// NewOmarchy finds the picker and checks that a display is available to show
// it.
func NewOmarchy() (*Omarchy, error) {
	path, err := lookup("omarchy-menu-select")
	if err != nil {
		return nil, fmt.Errorf("omarchy backend: %w", err)
	}
	return &Omarchy{binary: path, timeout: approvalTimeout}, nil
}

// Confirm shows title with choices and blocks until the user picks one. An
// empty choice means the user dismissed the prompt; an error means the prompt
// could not be shown at all, timed out, or ctx was cancelled.
func (m *Omarchy) Confirm(ctx context.Context, title string, choices []string) (string, error) {
	res, err := runPrompt(ctx, m.timeout, m.binary, append([]string{title}, choices...)...)
	if err != nil {
		return "", err
	}
	if res.exitCode != 0 {
		// A non-zero exit means either "dismissed with Escape" or "could not
		// launch". Those must not be conflated: the first is a decision, the
		// second is a broken prompt that would silently refuse every request.
		// Anything on stderr means the latter.
		if res.stderr != "" {
			return "", fmt.Errorf("approval prompt failed to run: %s", res.stderr)
		}
		return "", nil
	}
	// Options may carry a tab-separated subtext; the label is the first field.
	choice := res.stdout
	if i := strings.IndexByte(choice, '\t'); i >= 0 {
		choice = choice[:i]
	}
	return choice, nil
}
