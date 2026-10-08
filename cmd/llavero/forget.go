package main

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"llavero/internal/bootstrap"
	"llavero/internal/vault"
)

func forgetCommand() bootstrap.Command {
	return bootstrap.Command{
		Name:        "forget",
		Description: "delete passkeys matching a site or a credential id prefix",
		Options:     &forgetCmd{},
	}
}

type forgetCmd struct {
	vaultOptions

	Args struct {
		Match string `positional-arg-name:"SITE|ID"`
	} `positional-args:"yes" required:"yes"`
}

func (c *forgetCmd) Execute([]string) error {
	return c.withApp(func(a *app) error { return a.forget(c.Args.Match) })
}

// forget deletes credentials by site or by credential id prefix. It always
// shows what it is about to remove and asks first: there is no undo, and a
// deleted passkey may be the only way into an account.
func (a *app) forget(pattern string) error {
	if serviceHasOpen(a.opts.VaultPath) {
		return errors.New("the llavero service is running against this vault and holds its own\n" +
			"       copy in memory, so its next write would resurrect anything deleted here.\n" +
			"       Stop it first:  systemctl --user stop llavero.service")
	}

	v, err := a.loadVault("")
	if err != nil {
		return err // loadVault's errors already say what failed
	}

	needle := strings.ToLower(pattern)
	match := func(c vault.Credential) bool {
		return strings.ToLower(c.RPID) == needle ||
			strings.HasPrefix(strings.ToLower(fmt.Sprintf("%x", c.ID)), needle)
	}

	var doomed []vault.Credential
	for _, c := range v.List() {
		if match(c) {
			doomed = append(doomed, c)
		}
	}
	if len(doomed) == 0 {
		return fmt.Errorf("nothing in the vault matches %q (try: llavero list)", pattern)
	}

	fmt.Printf("\nAbout to delete %d passkey(s):\n\n", len(doomed))
	for _, c := range doomed {
		fmt.Printf("  %s  %s  %x  (used %d time(s))\n", c.RPID, c.UserName, c.ID[:8], c.SignCount)
	}
	// Echo the exact string back. Saying "type the site name" invites a near
	// miss on values like ".dummy", where the leading dot is easy to drop.
	fmt.Printf("\nThis cannot be undone. Type %q to confirm: ", pattern)

	var typed string
	fmt.Scanln(&typed)
	if strings.ToLower(strings.TrimSpace(typed)) != needle {
		return fmt.Errorf("confirmation did not match (wanted %q, got %q), nothing was deleted",
			pattern, strings.TrimSpace(typed))
	}

	gone, err := v.Remove(match)
	if err != nil {
		return fmt.Errorf("deleting passkeys: %w", err)
	}
	a.log.Info("deleted passkeys", zap.Int("deleted", len(gone)), zap.Int("remaining", v.Count()))
	return nil
}

// serviceHasOpen reports whether the running service is using this very vault.
// Editing a different file while the daemon runs is harmless, so the guard is
// scoped to the path rather than refusing whenever the service happens to be up.
func serviceHasOpen(vaultPath string) bool {
	out, err := exec.Command("systemctl", "--user", "is-active", "llavero.service").Output()
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return false
	}

	// The unit passes no --vault, so the service is on the default path. If it
	// ever gains one, prefer what the unit actually says.
	servicePath := vault.DefaultPath()
	if line, err := exec.Command("systemctl", "--user", "show", "-p", "ExecStart",
		"--value", "llavero.service").Output(); err == nil {
		fields := strings.Fields(string(line))
		for i, f := range fields {
			if path, ok := strings.CutPrefix(f, "--vault="); ok {
				servicePath = path
			} else if f == "--vault" && i+1 < len(fields) {
				servicePath = fields[i+1]
			}
		}
	}
	return sameFile(vaultPath, servicePath)
}

// sameFile compares paths after resolving symlinks, falling back to a cleaned
// absolute comparison when a path does not exist yet.
func sameFile(a, b string) bool {
	resolve := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return real
		}
		return filepath.Clean(p)
	}
	return resolve(a) == resolve(b)
}
