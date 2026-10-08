package main

import (
	"fmt"
	"llavero/internal/bootstrap"
)

func listCommand() bootstrap.Command {
	return bootstrap.Command{
		Name:        "list",
		Description: "list stored passkeys",
		Options:     &listCmd{},
	}
}

type listCmd struct {
	vaultOptions
}

func (c *listCmd) Execute([]string) error {
	return c.withApp((*app).list)
}

// list prints what is in the vault. Useful on its own, and the only way to
// find the id of something worth deleting.
func (a *app) list() error {
	v, err := a.loadVault("")
	if err != nil {
		return err // loadVault's errors already say what failed
	}
	creds := v.List()
	if len(creds) == 0 {
		fmt.Println("\nThe vault is empty.")
		return nil
	}
	fmt.Printf("\n%-28s  %-34s  %-16s  %5s  %s\n", "SITE", "ACCOUNT", "CREDENTIAL", "USES", "CREATED")
	for _, c := range creds {
		account := c.UserName
		if account == "" {
			account = c.UserDisplay
		}
		fmt.Printf("%-28s  %-34s  %-16x  %5d  %s\n",
			truncate(c.RPID, 28), truncate(account, 34), c.ID[:8], c.SignCount,
			c.CreatedAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Printf("\n%d passkey(s).\n", len(creds))
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "\u2026"
}
