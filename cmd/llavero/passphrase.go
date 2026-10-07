package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

func readPassphrase(passFD int, confirm bool, adjective string) ([]byte, error) {
	if passFD >= 0 {
		f := os.NewFile(uintptr(passFD), "passphrase")
		if f == nil {
			return nil, fmt.Errorf("file descriptor %d is not open", passFD)
		}
		// Read one byte at a time up to the newline. A buffered reader would
		// read ahead and swallow whatever else the caller piped in, such as
		// the confirmation a later prompt asks for.
		line, err := readLine(f)
		if err != nil && len(line) == 0 {
			return nil, fmt.Errorf("reading passphrase from fd %d: %w", passFD, err)
		}
		if passFD != 0 {
			f.Close()
		}
		return line, nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("no terminal to read the passphrase from (use -passphrase-fd)")
	}

	if confirm {
		fmt.Printf("Choose a %spassphrase (this encrypts every passkey): ", adjective)
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		if len(first) < 8 {
			zero(first)
			return nil, errors.New("passphrase must be at least 8 characters")
		}
		fmt.Print("Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, err
		}
		defer zero(second)
		if string(first) != string(second) {
			zero(first)
			return nil, errors.New("passphrases do not match")
		}
		fmt.Println("\nKeep this passphrase safe. There is no recovery path:")
		fmt.Println("lose it and every passkey in the vault is gone.")
		return first, nil
	}

	fmt.Print("Vault passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return pass, err
}

// readLine consumes exactly one line and not a byte more, so the rest of the
// stream stays available to whoever reads next.
func readLine(f *os.File) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1)
	for len(out) < 4096 {
		n, err := f.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				break
			}
			out = append(out, buf[0])
		}
		if err != nil {
			return bytes.TrimRight(out, "\r"), err
		}
	}
	return bytes.TrimRight(out, "\r"), nil
}

// zero overwrites secret material so it does not linger in the heap any longer
// than necessary.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
