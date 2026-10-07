// Package fingerprint verifies the user through fprintd.
//
// fprintd owns the sensor exclusively, so every check claims the device, runs
// one verification, and releases it again. Holding the claim between requests
// would block the login screen and polkit prompts.
package fingerprint

import (
	"errors"
	"fmt"
	"os/user"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	fprintService   = "net.reactivated.Fprint"
	fprintManager   = "/net/reactivated/Fprint/Manager"
	fprintDeviceIfc = "net.reactivated.Fprint.Device"
	fprintMgrIfc    = "net.reactivated.Fprint.Manager"

	// A scan takes a couple of seconds, but the user has to notice the prompt
	// first, and Chrome may be racing its own passkey provider for their
	// attention. This bound only exists so a sensor that stops reporting
	// cannot hang an authentication forever.
	fingerprintTimeout = 35 * time.Second
)

// ErrUnavailable means the sensor could not be used at all, as opposed to the
// finger not matching. Callers treat the two very differently.
var ErrUnavailable = errors.New("fingerprint sensor unavailable")

// Prompter shows the user a sticky "touch the sensor" message for the length
// of a scan.
type Prompter interface {
	Prompt(summary, body string)
	DismissPrompt()
}

// Verifier runs one fprintd verification per request for the current user.
type Verifier struct {
	username string
	prompter Prompter
	logf     func(string, ...any)
}

// New checks that fprintd has a sensor with a finger enrolled for the current
// user, so a missing enrolment shows up at startup rather than at the first
// sign-in.
func New(prompter Prompter, logf func(string, ...any)) (*Verifier, error) {
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("looking up current user: %w", err)
	}
	fv := &Verifier{username: u.Username, prompter: prompter, logf: logf}

	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("connecting to the system bus: %w", err)
	}
	devPath, err := defaultDevice(conn)
	if err != nil {
		return nil, err
	}
	dev := conn.Object(fprintService, devPath)
	var fingers []string
	if err := dev.Call(fprintDeviceIfc+".ListEnrolledFingers", 0, fv.username).Store(&fingers); err != nil {
		return nil, fmt.Errorf("listing enrolled fingers: %w", err)
	}
	if len(fingers) == 0 {
		return nil, fmt.Errorf("no fingerprints enrolled for %s (run fprintd-enroll)", fv.username)
	}
	logf("fingerprint verification enabled (%d finger(s) enrolled)", len(fingers))
	return fv, nil
}

func defaultDevice(conn *dbus.Conn) (dbus.ObjectPath, error) {
	mgr := conn.Object(fprintService, fprintManager)
	var devPath dbus.ObjectPath
	if err := mgr.Call(fprintMgrIfc+".GetDefaultDevice", 0).Store(&devPath); err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return devPath, nil
}

// Verify runs one scan. It returns (true, nil) on a match, (false, nil) on a
// genuine non-match, and an error wrapping ErrUnavailable only when the sensor
// could not be used.
func (fv *Verifier) Verify(reason string) (bool, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	devPath, err := defaultDevice(conn)
	if err != nil {
		return false, err
	}
	dev := conn.Object(fprintService, devPath)

	if call := dev.Call(fprintDeviceIfc+".Claim", 0, fv.username); call.Err != nil {
		return false, fmt.Errorf("%w: claiming the sensor: %v", ErrUnavailable, call.Err)
	}
	defer dev.Call(fprintDeviceIfc+".Release", 0)

	// Subscribe before starting, so a fast scan cannot complete before we are
	// listening and leave us waiting for a signal that already fired.
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(devPath),
		dbus.WithMatchInterface(fprintDeviceIfc),
		dbus.WithMatchMember("VerifyStatus"),
	); err != nil {
		return false, fmt.Errorf("%w: subscribing to VerifyStatus: %v", ErrUnavailable, err)
	}
	defer conn.RemoveMatchSignal(
		dbus.WithMatchObjectPath(devPath),
		dbus.WithMatchInterface(fprintDeviceIfc),
		dbus.WithMatchMember("VerifyStatus"),
	)

	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	if call := dev.Call(fprintDeviceIfc+".VerifyStart", 0, "any"); call.Err != nil {
		return false, fmt.Errorf("%w: starting verification: %v", ErrUnavailable, call.Err)
	}
	defer dev.Call(fprintDeviceIfc+".VerifyStop", 0)

	fv.prompter.Prompt("Touch the fingerprint sensor", reason)
	defer fv.prompter.DismissPrompt()
	fv.logf("waiting for fingerprint: %s", reason)

	deadline := time.After(fingerprintTimeout)
	for {
		select {
		case <-deadline:
			return false, fmt.Errorf("%w: no response from the sensor in %s",
				ErrUnavailable, fingerprintTimeout)

		case sig := <-signals:
			if sig == nil || sig.Name != fprintDeviceIfc+".VerifyStatus" || len(sig.Body) < 2 {
				continue
			}
			result, _ := sig.Body[0].(string)
			done, _ := sig.Body[1].(bool)

			if !done {
				// Retryable conditions: finger moved, scan too short. The
				// sensor keeps reading, so keep waiting.
				fv.logf("fingerprint retry: %s", result)
				continue
			}
			switch result {
			case "verify-match":
				return true, nil
			case "verify-no-match":
				return false, nil
			case "verify-disconnected":
				return false, fmt.Errorf("%w: sensor disconnected mid-scan", ErrUnavailable)
			default:
				return false, fmt.Errorf("%w: %s", ErrUnavailable, result)
			}
		}
	}
}
