package approval

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakePrompt writes a shell script standing in for a prompt program.
func fakePrompt(t *testing.T, body string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "prompt")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return binary
}

type promptCase struct {
	name    string
	script  string
	choices []string
	want    string
	wantErr string
}

func runCases(t *testing.T, cases []promptCase, newPrompt func(binary string) Prompt) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binary := fakePrompt(t, tc.script)
			choices := tc.choices
			if choices == nil {
				choices = []string{"Sign in", "Cancel"}
			}
			got, err := newPrompt(binary).Confirm(context.Background(), "Sign in to example.com?", choices)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("choice = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOmarchyConfirm(t *testing.T) {
	runCases(t, []promptCase{
		{name: "picked", script: "echo 'Sign in'", want: "Sign in"},
		{name: "subtext stripped", script: "printf 'Sign in\\tas alice\\n'", want: "Sign in"},
		{name: "dismissed", script: "exit 1", want: ""},
		{name: "failed to launch", script: "echo 'no menu' >&2; exit 1", wantErr: "no menu"},
		{name: "timed out", script: "exec sleep 5", wantErr: "timed out"},
	}, func(binary string) Prompt {
		return &Omarchy{binary: binary, timeout: 200 * time.Millisecond}
	})
}

func TestZenityConfirm(t *testing.T) {
	accounts := []string{"alice", "bob", "carol", "dave"}
	runCases(t, []promptCase{
		{name: "button picked", script: "echo 'Sign in'; exit 1", want: "Sign in"},
		{name: "cancel button", script: "echo Cancel; exit 1", want: "Cancel"},
		{name: "dismissed", script: "exit 1", want: ""},
		{name: "list row picked", script: "echo carol", choices: accounts, want: "carol"},
		{name: "list ok with nothing selected", script: "exit 0", choices: accounts, want: ""},
		// A bare exit 0 is how zenity reports its own OK button. Without a
		// label it must not read as consent.
		{name: "silent success is not consent", script: "exit 0", want: ""},
		{name: "answer outside the choices", script: "echo Yes; exit 0", wantErr: "not one of the choices"},
		{name: "failed to open display", script: "echo 'Failed to open display' >&2; exit 1", wantErr: "Failed to open display"},
		{name: "zenity error", script: "exit 255", wantErr: "exit 255"},
		{name: "zenity timeout code", script: "echo alice; exit 5", choices: accounts, wantErr: "exit 5"},
		{name: "timed out", script: "exec sleep 5", wantErr: "timed out"},
	}, func(binary string) Prompt {
		return &Zenity{binary: binary, timeout: 200 * time.Millisecond}
	})
}

func TestZenityCancelledByHost(t *testing.T) {
	binary := fakePrompt(t, "exec sleep 5")
	z := &Zenity{binary: binary, timeout: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := z.Confirm(ctx, "Sign in?", []string{"Sign in", "Cancel"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err = %v, want cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("prompt outlived the request by %v", elapsed)
	}
}

func TestZenityArgs(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		choices []string
		want    []string
		notWant []string
	}{
		{
			name:    "buttons",
			title:   "Sign in to <b>x</b>?",
			choices: []string{"Sign in", "Cancel"},
			want:    []string{"--question", "--switch", "--no-markup", "--text=Sign in to <b>x</b>?", "--extra-button=Sign in", "--extra-button=Cancel"},
			notWant: []string{"--list", "--timeout"},
		},
		{
			name:    "list escapes title and fences rows",
			title:   "Sign in to a&b <c> as:",
			choices: []string{"alice", "bob", "--ok-label=x", "dave"},
			want:    []string{"--list", "--text=Sign in to a&amp;b &lt;c&gt; as:", "--", "--ok-label=x"},
			notWant: []string{"--question", "--timeout"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := zenityArgs(tc.title, tc.choices)
			for _, w := range tc.want {
				if !slices.Contains(args, w) {
					t.Errorf("args %q lack %q", args, w)
				}
			}
			for _, nw := range tc.notWant {
				for _, a := range args {
					if strings.HasPrefix(a, nw) {
						t.Errorf("args %q contain %q", args, nw)
					}
				}
			}
			if i := slices.Index(args, "--"); i >= 0 && !slices.Equal(args[i+1:], tc.choices) {
				t.Errorf("rows after -- = %q, want %q", args[i+1:], tc.choices)
			}
		})
	}
}

func TestNew(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"zenity", "omarchy-menu-select"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	onlyZenity := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "zenity"), filepath.Join(onlyZenity, "zenity")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		backend string
		path    string
		display string
		want    string
		wantErr string
	}{
		{name: "auto prefers omarchy", backend: BackendAuto, path: dir, display: "wayland-0", want: "*approval.Omarchy"},
		{name: "auto falls back to zenity", backend: BackendAuto, path: onlyZenity, display: "wayland-0", want: "*approval.Zenity"},
		{name: "explicit zenity", backend: BackendZenity, path: dir, display: "wayland-0", want: "*approval.Zenity"},
		{name: "nothing installed", backend: BackendAuto, path: t.TempDir(), display: "wayland-0", wantErr: "no approval backend"},
		{name: "explicit backend missing", backend: BackendOmarchy, path: onlyZenity, display: "wayland-0", wantErr: "omarchy-menu-select not found"},
		{name: "no display", backend: BackendZenity, path: dir, wantErr: "no WAYLAND_DISPLAY"},
		{name: "unknown backend", backend: "kdialog", path: dir, display: "wayland-0", wantErr: "unknown approval backend"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			t.Setenv("WAYLAND_DISPLAY", tc.display)
			t.Setenv("DISPLAY", "")
			got, err := New(tc.backend)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotType := typeName(got); gotType != tc.want {
				t.Fatalf("backend = %s, want %s", gotType, tc.want)
			}
		})
	}
}

func typeName(p Prompt) string {
	switch p.(type) {
	case *Omarchy:
		return "*approval.Omarchy"
	case *Zenity:
		return "*approval.Zenity"
	default:
		return "unknown"
	}
}
