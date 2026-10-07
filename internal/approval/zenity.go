package approval

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// maxButtons is how many choices still fit as buttons. More than that, such
// as a long list of accounts at one site, become a list to pick from.
const maxButtons = 3

// Zenity drives zenity, the GNOME dialog tool, which also runs on any other
// GTK-capable desktop.
type Zenity struct {
	binary  string
	timeout time.Duration
}

// NewZenity finds zenity and checks that a display is available to show it.
func NewZenity() (*Zenity, error) {
	path, err := lookup("zenity")
	if err != nil {
		return nil, fmt.Errorf("zenity backend: %w", err)
	}
	return &Zenity{binary: path, timeout: approvalTimeout}, nil
}

// Confirm shows title with choices and blocks until the user picks one. An
// empty choice means the user dismissed the prompt; an error means the prompt
// could not be shown at all, gave an answer that is not one of the choices,
// timed out, or ctx was cancelled.
//
// zenity's own --timeout is never used: on expiry a list prints its
// preselected row, which would read as a decision nobody made. The deadline is
// enforced by killing the process instead.
func (z *Zenity) Confirm(ctx context.Context, title string, choices []string) (string, error) {
	res, err := runPrompt(ctx, z.timeout, z.binary, zenityArgs(title, choices)...)
	if err != nil {
		return "", err
	}
	// Approval rests on zenity printing the label of what was picked, never on
	// the exit code alone: a question dialog exits 0 for its OK button, so a
	// prompt that fails in a way that exits 0 must not count as consent.
	// Buttons print their label and exit 1, a list prints its row and exits 0,
	// and closing either exits 1 with nothing printed.
	switch {
	case res.exitCode > 1:
		return "", fmt.Errorf("approval prompt failed to run (exit %d): %s", res.exitCode, res.stderr)
	case res.stdout != "":
		if !slices.Contains(choices, res.stdout) {
			return "", fmt.Errorf("approval prompt answered %q, which is not one of the choices", res.stdout)
		}
		return res.stdout, nil
	case res.exitCode == 1 && res.stderr != "":
		// Dismissing a dialog is silent; GTK failing to open one is not.
		return "", fmt.Errorf("approval prompt failed to run: %s", res.stderr)
	default:
		return "", nil
	}
}

// zenityArgs builds the command line: a button per choice when they fit,
// otherwise a list.
func zenityArgs(title string, choices []string) []string {
	args := []string{"--title=Llavero"}
	if len(choices) <= maxButtons {
		// --switch drops zenity's own OK and Cancel, leaving one button per
		// choice. --no-markup keeps a site name from being read as Pango
		// markup.
		args = append(args, "--question", "--switch", "--no-markup", "--icon=dialog-password", "--text="+title)
		for _, c := range choices {
			args = append(args, "--extra-button="+c)
		}
		return args
	}
	// List text is always markup, so escape it. The rows come from the site
	// (account names), so "--" keeps one shaped like a flag from being parsed
	// as one.
	args = append(args, "--list", "--hide-header", "--column=Account", "--text="+escapeMarkup(title), "--")
	return append(args, choices...)
}

var markupEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func escapeMarkup(s string) string {
	return markupEscaper.Replace(s)
}
