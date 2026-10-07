package hardening

import (
	"testing"

	"go.uber.org/zap/zaptest"
	"golang.org/x/sys/unix"
)

// The core-dump protections must actually be in effect afterwards, not merely
// attempted. This mutates the test process, which is harmless: a hard
// RLIMIT_CORE of zero and a cleared dumpable flag affect nothing else here.
//
// Memory locking is deliberately left out. Whether mlockall succeeds depends
// on RLIMIT_MEMLOCK, which varies by machine and by how the test was launched,
// so asserting on it would make the suite fail for environmental reasons
// rather than for bugs.
func TestHardeningDisablesCoreDumps(t *testing.T) {
	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil {
		t.Fatalf("reading RLIMIT_CORE: %v", err)
	}
	t.Logf("RLIMIT_CORE before: cur=%d max=%d", before.Cur, before.Max)

	Apply(false, zaptest.NewLogger(t))

	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatalf("reading RLIMIT_CORE: %v", err)
	}
	if after.Cur != 0 || after.Max != 0 {
		t.Errorf("RLIMIT_CORE is cur=%d max=%d, want 0/0; a crash could write "+
			"the vault's private keys to disk", after.Cur, after.Max)
	}

	// The hard limit must be zero too, so nothing can raise it again later.
	raise := unix.Rlimit{Cur: 1024, Max: 1024}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &raise); err == nil {
		t.Error("RLIMIT_CORE was raised again after hardening; the hard limit did not stick")
	}

	if d := dumpable(); d != 0 {
		t.Errorf("PR_GET_DUMPABLE is %d, want 0; other processes running as this "+
			"user may be able to read the vault out of memory", d)
	}
}

// dumpable() has to distinguish "cannot read" from "is zero", or a broken
// readback would look like success.
func TestDumpableReadbackWorks(t *testing.T) {
	if d := dumpable(); d < 0 {
		t.Skip("PR_GET_DUMPABLE unavailable on this kernel")
	} else if d != 0 && d != 1 && d != 2 {
		t.Errorf("PR_GET_DUMPABLE returned %d, which is not a documented value", d)
	}
}
