package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// readLine must stop at the newline and leave the rest of the stream for the
// next reader, which is how -passphrase-fd feeds a passphrase and its
// confirmation through one pipe.
func TestReadLineLeavesTheRest(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{"two lines", "first\nsecond\n", []string{"first", "second"}, false},
		{"CRLF", "first\r\nsecond\r\n", []string{"first", "second"}, false},
		{"no trailing newline", "only", []string{"only"}, true},
		{"empty line", "\nnext\n", []string{"", "next"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := w.WriteString(tt.input); err != nil {
				t.Fatal(err)
			}
			w.Close()

			var lastErr error
			for i, want := range tt.want {
				got, err := readLine(r)
				lastErr = err
				if string(got) != want {
					t.Fatalf("line %d = %q, want %q", i, got, want)
				}
			}
			if gotErr := errors.Is(lastErr, io.EOF); gotErr != tt.wantErr {
				t.Fatalf("last error = %v, want EOF: %v", lastErr, tt.wantErr)
			}
		})
	}
}

func TestReadLineCapsLength(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() {
		defer w.Close()
		buf := make([]byte, 5000)
		for i := range buf {
			buf[i] = 'x'
		}
		w.Write(buf)
	}()
	got, err := readLine(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4096 {
		t.Fatalf("read %d bytes, want the 4096 cap", len(got))
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly", 7, "exactly"},
		{"too long", 5, "too …"},
		{"ab", 1, "a"},
	}
	for _, tt := range tests {
		if got := truncate(tt.in, tt.n); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "vault.pkv")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pkv")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", real, real, true},
		{"through symlink", link, real, true},
		{"unclean path", filepath.Join(dir, ".", "sub", "..", "vault.pkv"), real, true},
		{"different file", real, filepath.Join(dir, "other.pkv"), false},
		{"neither exists", filepath.Join(dir, "x"), filepath.Join(dir, "x"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sameFile(tt.a, tt.b); got != tt.want {
				t.Fatalf("sameFile(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
