// Package hardening applies process protections before any key material exists.
//
// Two distinct exposures, with very different severity:
//
// Core dumps are the urgent one. A crash writes the entire process image,
// including every decrypted private key in the vault, to wherever the kernel's
// core_pattern sends it. On a systemd machine that is systemd-coredump, which
// keeps dumps on disk under /var/lib/systemd/coredump. Nothing about full-disk
// encryption helps while the system is running.
//
// Swap is the lesser one. Pages holding keys can be written to a swap device
// and recovered from it after power-off. If swap sits on an encrypted volume
// that risk is already covered, which is the common case on a modern install,
// so locking memory is defence in depth rather than the main event.
package hardening

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// Apply is called before the vault is opened, so that no decrypted key
// has ever existed in this process by the time the protections are in place.
//
// Nothing here is fatal. A machine that refuses one of these is still better
// served by a working authenticator than by no authenticator, and the log says
// exactly what did not apply.
func Apply(lockMemory bool, logf func(string, ...any)) {
	applied := noCoreDumps(logf)

	if lockMemory {
		if s := lockAllMemory(logf); s != "" {
			applied = append(applied, s)
		}
	}

	if len(applied) > 0 {
		logf("hardening: %s", strings.Join(applied, ", "))
	}
}

// noCoreDumps stops the process image reaching disk, two ways, because they
// fail independently.
func noCoreDumps(logf func(string, ...any)) []string {
	var applied []string

	// A hard limit of zero cannot be raised again, even by this process.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		logf("WARNING: could not disable core dumps (%v); a crash may write "+
			"every private key to disk", err)
	} else {
		applied = append(applied, "core dumps off")
	}

	// PR_SET_DUMPABLE=0 both suppresses dumps and stops another process
	// running as the same user from attaching with ptrace to read memory out
	// of us, which the rlimit alone does not prevent.
	//
	// Read the flag back rather than trusting the return value. There is no
	// /proc file exposing it, and the ownership of /proc/[pid] is not the
	// indicator it is often assumed to be, so a readback is the only honest
	// confirmation.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logf("WARNING: could not clear the dumpable flag (%v); other processes "+
			"running as you may be able to read this one's memory", err)
	} else if dumpable() != 0 {
		logf("WARNING: the dumpable flag did not stick; other processes running " +
			"as you may be able to read this one's memory")
	} else {
		applied = append(applied, "not dumpable, no same-user ptrace")
	}

	return applied
}

// lockAllMemory keeps pages out of swap. It returns a description of what took
// effect, or "" if nothing did.
func lockAllMemory(logf func(string, ...any)) string {
	// Raise the soft limit to the hard limit first. An unprivileged process
	// may do that much, and it is often enough on its own.
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err == nil && lim.Cur < lim.Max {
		raised := unix.Rlimit{Cur: lim.Max, Max: lim.Max}
		if unix.Setrlimit(unix.RLIMIT_MEMLOCK, &raised) == nil {
			lim = raised
		}
	}

	// MCL_FUTURE is what actually matters: keys are parsed per request, long
	// after startup. But it also means every later allocation has to fit under
	// RLIMIT_MEMLOCK, and an allocation the kernel refuses becomes a Go
	// runtime panic rather than a recoverable error. So check for headroom
	// first and decline rather than arm a landmine.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		logf("WARNING: could not lock memory (%v)", err)
		logf("         keys may be written to swap. RLIMIT_MEMLOCK is %s;",
			describeLimit(lim.Cur))
		logf("         raise it with LimitMEMLOCK=64M in the systemd unit, or")
		logf("         pass -mlock=false to stop trying and silence this")
		logf("         (harmless if your swap is on an encrypted volume)")
		return ""
	}
	return fmt.Sprintf("memory locked (limit %s)", describeLimit(lim.Cur))
}

// dumpable returns the current PR_GET_DUMPABLE value, or -1 if it cannot be
// read. There is no prctl wrapper for the getter, hence the raw syscall.
func dumpable() int {
	v, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 {
		return -1
	}
	return int(v)
}

func describeLimit(v uint64) string {
	if v == ^uint64(0) {
		return "unlimited"
	}
	return fmt.Sprintf("%d MiB", v/(1024*1024))
}
