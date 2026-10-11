package ais140_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/track"
)

// On AIS-140 reboot is Table 4D SET 018 and interval SET 014, framed with
// the device's password; engine stop and locate are not in Table 4D and
// fail with the reason unless the profile gives the maker's line, which is
// sent as it is.
//
// Covers: SIG-IMP-008
func TestNamedCommandsTable4D(t *testing.T) {
	dev := &device{IMEI: imei, CommandPassword: "1234"}
	for action, want := range map[string]string{"reboot": imei + ",1234,SET,018:1*", "interval": imei + ",1234,SET,014:30*"} {
		b, answers, err := commandForTest(`{}`, dev, map[string]any{"action": action, "seconds": 30.0})
		if action == "reboot" {
			b, answers, err = commandForTest(`{}`, dev, map[string]any{"action": action})
		}
		if err != nil || !answers || !strings.Contains(string(b), want) {
			t.Errorf("%s: %q %v", action, b, err)
		}
	}
	for _, a := range []string{"engineStop", "engineResume", "locate"} {
		if _, _, err := commandForTest(`{}`, dev, map[string]any{"action": a}); !errors.Is(err, track.ErrUnsupported) {
			t.Errorf("%s: %v", a, err)
		}
	}
	b, _, err := commandForTest(`{"namedCommands": {"engineStop": "@SET#RLP,OP1,{password}"}}`, dev, map[string]any{"action": "engineStop"})
	if err != nil || string(b) != "@SET#RLP,OP1,1234\r\n" {
		t.Errorf("template: %q %v", b, err)
	}
}
