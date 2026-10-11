package teltonika_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cB-Sigma/trackers/teltonika"
	"github.com/cB-Sigma/trackers/track"
)

// Named commands are Teltonika SMS/GPRS commands in Codec 12; the
// interval defaults to the FMB data-acquisition parameters and a profile
// template replaces it (or turns it off) for other models.
//
// Covers: SIG-IMP-008
func TestNamedCommandTexts(t *testing.T) {
	nc, err := teltonika.NewCodec(nil)
	if err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]string{"engineStop": "setdigout 1", "engineResume": "setdigout 0", "locate": "getrecord", "reboot": "cpureset"} {
		f, answers, err := nc().Command("356307042441013", map[string]any{"action": action}, 1)
		if err != nil || !answers || string(f) != string(teltonika.Codec12Frame(teltonika.TypeCmd, want)) {
			t.Errorf("%s: %q %v", action, f, err)
		}
	}
	// The interval is FMB setparam of the data-acquisition "Min Period"
	// parameters: on stop and moving, in the home, roaming and unknown
	// networks.
	f, _, err := nc().Command("356307042441013", map[string]any{"action": "interval", "seconds": 60.0}, 1)
	if err != nil || string(f) != string(teltonika.Codec12Frame(teltonika.TypeCmd, "setparam 10000:60;10050:60;10100:60;10150:60;10200:60;10250:60")) {
		t.Errorf("interval default: %q %v", f, err)
	}
	// A profile that turns it off answers unsupported.
	off, err := teltonika.NewCodec(json.RawMessage(`{"namedCommands": {"interval": ""}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := off().Command("356307042441013", map[string]any{"action": "interval", "seconds": 60.0}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Errorf("interval turned off: %v", err)
	}
	nc, err = teltonika.NewCodec(json.RawMessage(`{"namedCommands": {"interval": "setparam 10050:{seconds}", "engineStop": "setdigout ?1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]string{"interval": "setparam 10050:60", "engineStop": "setdigout ?1"} {
		f, _, err := nc().Command("356307042441013", map[string]any{"action": action, "seconds": 60.0}, 1)
		if action == "engineStop" {
			f, _, err = nc().Command("356307042441013", map[string]any{"action": action}, 1)
		}
		if err != nil || string(f) != string(teltonika.Codec12Frame(teltonika.TypeCmd, want)) {
			t.Errorf("%s: %q %v", action, f, err)
		}
	}
}
