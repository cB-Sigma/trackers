package gt06_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/gt06"
)

// Named commands go out as the Concox command texts; a profile template
// replaces one; an interval outside 10 to 18000 s and unknown members are
// refused before anything is sent.
//
// Covers: SIG-IMP-006
func TestNamedCommandTexts(t *testing.T) {
	nc, err := gt06.NewCodec(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		content map[string]any
		want    string
	}{
		{map[string]any{"action": "engineStop"}, "RELAY,1#"},
		{map[string]any{"action": "engineStop", "force": true}, "RELAY,1#"},
		{map[string]any{"action": "engineResume"}, "RELAY,0#"},
		{map[string]any{"action": "locate"}, "WHERE#"},
		{map[string]any{"action": "reboot"}, "RESET#"},
		{map[string]any{"action": "interval", "seconds": 30.0}, "TIMER,30#"},
	} {
		f, answers, err := nc().Command(imei, tc.content, 7)
		if err != nil || !answers || !strings.Contains(string(f), tc.want) {
			t.Errorf("%v: %q %v %v", tc.content, f, answers, err)
		}
	}
	for _, bad := range []map[string]any{
		{"action": "interval", "seconds": 5.0},
		{"action": "interval"},
		{"action": "locate", "seconds": 5.0},
		{"action": "reboot", "force": true},
		{"action": "selfDestruct"},
	} {
		if _, _, err := nc().Command(imei, bad, 1); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	nc, err = gt06.NewCodec(json.RawMessage(`{"namedCommands": {"engineStop": "DYD,000000#", "reboot": ""}}`))
	if err != nil {
		t.Fatal(err)
	}
	if f, _, err := nc().Command(imei, map[string]any{"action": "engineStop"}, 1); err != nil || !strings.Contains(string(f), "DYD,000000#") {
		t.Errorf("template: %q %v", f, err)
	}
	if _, _, err := nc().Command(imei, map[string]any{"action": "reboot"}, 1); err == nil || !strings.Contains(err.Error(), "no reboot command") {
		t.Errorf("turned-off reboot: %v", err)
	}
	for _, bad := range []string{`{"namedCommands": {"selfDestruct": "X#"}}`, `{"namedCommands": {"engineStop": "DYD,{password}#"}}`, `{"namedCommands": {"locate": "WHERE,{seconds}#"}}`} {
		if _, err := gt06.NewCodec(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

const imei = "359710049099999"
