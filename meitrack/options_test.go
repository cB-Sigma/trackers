package meitrack_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/meitrack"
	"github.com/cB-Sigma/trackers/track"
)

func codec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := meitrack.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatalf("%s: %v", profile, err)
	}
	return nc()
}

// Named and text commands produce the documents' frames byte for byte (the
// sequence picks the data identifier), and the correlation names the
// identifier and command type the answer carries.
//
// Covers: SIG-IMP-027
func TestCommandBytes(t *testing.T) {
	for _, x := range []struct {
		profile string
		content map[string]any
		seq     uint32
		want    string
		corr    string
	}{
		{"", map[string]any{"action": "locate"}, 17, vA10, "Q:A10"},
		{"", map[string]any{"action": "interval", "seconds": 60}, 22, vA12, "V:A12"},
		{"", map[string]any{"text": "C01,20,10122"}, 13, vC01, "M:C01"},
		{`{"namedCommands": {"reboot": "F00,1,1"}}`, map[string]any{"action": "reboot"}, 36, vF00, "j:F00"},
		{"", map[string]any{"action": "engineStop"}, 1, "@@A33,353358017784062,C01,0,12222*", "A:C01"},
		{`{"relayOutput": 2, "stopSpeed": 20}`, map[string]any{"action": "engineStop"}, 1, "@@A34,353358017784062,C01,20,21222*", "A:C01"},
		{`{"relayOutput": 2}`, map[string]any{"action": "engineResume"}, 1, "@@A33,353358017784062,C01,0,20222*", "A:C01"},
		{`{"relayInverted": true}`, map[string]any{"action": "engineStop"}, 1, "@@A33,353358017784062,C01,0,02222*", "A:C01"},
		{`{"matchIdentifier": false}`, map[string]any{"action": "locate"}, 1, "@@A25,353358017784062,A10*", "A10"},
	} {
		c := codec(t, x.profile)
		f, answers, err := c.Command(docIMEI, x.content, x.seq)
		if err != nil || !answers || !strings.HasPrefix(string(f), x.want) {
			t.Errorf("%s %v: %q %v %v, want %q", x.profile, x.content, f, answers, err, x.want)
		}
		if corr, strict := c.(track.Correlator).Correlation(x.content, x.seq); corr != x.corr || !strict {
			t.Errorf("%s %v: correlation %q", x.profile, x.content, corr)
		}
	}
	c := codec(t, "")
	for _, bad := range []map[string]any{
		{"action": "interval", "seconds": 65}, {"action": "interval", "seconds": 5}, {"text": "C01,0,1*"},
		{"text": "hello"}, {"text": strings.Repeat("A", 201)},
	} {
		if _, _, err := c.Command(docIMEI, bad, 1); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	_, _, err := c.Command(docIMEI, map[string]any{"action": "reboot"}, 1)
	if !errors.Is(err, track.ErrUnsupported) || !strings.Contains(err.Error(), "namedCommands.reboot") {
		t.Fatalf("reboot: %v", err)
	}
}

// Profile options: confirmEvents answers reports with AFF,1; events adds,
// changes and drops alerts; ignitionInput 0 reports no ignition;
// failureWords; bad values are refused with the reason.
//
// Covers: SIG-IMP-028
func TestProfileOptions(t *testing.T) {
	ms := decodeAll(t, `{"confirmEvents": true}`, b(vSOS), b("$$G28,353358017784062,AFF,OK*00\r\n"))
	if len(ms) < 1 || ms[0] == nil || !strings.HasPrefix(string(ms[0].Reply), "@@G27,353358017784062,AFF,1*") {
		t.Fatalf("confirm: %+v", ms)
	}
	if ms := decodeAll(t, "", b(vSOS)); ms[0].Reply != nil {
		t.Fatal("a report was answered without confirmEvents")
	}
	ms = decodeAll(t, `{"events": {"1": "", "34": "tamper"}, "ignitionInput": 0}`, b(vSOS), b(vA10Answer))
	if len(ms[0].Records[0].Alerts) != 0 || ms[1].Records[0].Alerts[0].Type != "tamper" || ms[1].Records[0].Status["ignition"] != nil {
		t.Fatalf("events: %+v %+v", ms[0].Records[0], ms[1].Records[0])
	}
	ms = decodeAll(t, `{"failureWords": ["ok"]}`, b(vC01Answer))
	if !ms[0].Failed {
		t.Fatal("failureWords not applied")
	}
	for _, p := range []string{`{"relayOutput": 6}`, `{"stopSpeed": 300}`, `{"ignitionInput": 9}`, `{"analog": "x"}`,
		`{"events": {"x": "y"}}`, `{"namedCommands": {"reboot": "F00,{password}"}}`, `{"timezone": "Mars/Base"}`, `{"nope": 1}`} {
		if _, err := meitrack.NewCodec(json.RawMessage(p)); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
