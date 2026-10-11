package h02_test

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/h02"
	"github.com/cB-Sigma/trackers/track"
)

const imei = "353505910449999"

func codec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := h02.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

type correlator interface {
	Correlation(content any, seq uint32) (string, bool)
}

// The named commands produce the V1.0.5 document's frames (S20 with the
// time and 1,1 / 1,0; CR; CQ; XT,<seconds>), every one is answered, and the
// correlation of each is its command word with the time it carries.
//
// Covers: SIG-IMP-040
func TestNamedCommandFrames(t *testing.T) {
	c := codec(t, "")
	cases := []struct {
		content map[string]any
		re      string
		corr    string // regexp
	}{
		{map[string]any{"action": "engineStop"}, `^\*HQ,` + imei + `,S20,(\d{6}),1,1#$`, `^S20,\d{6}$`},
		{map[string]any{"action": "engineResume"}, `^\*HQ,` + imei + `,S20,(\d{6}),1,0#$`, `^S20,\d{6}$`},
		{map[string]any{"action": "locate"}, `^\*HQ,` + imei + `,CR#$`, `^CR$`},
		{map[string]any{"action": "reboot"}, `^\*HQ,` + imei + `,CQ#$`, `^CQ$`},
		{map[string]any{"action": "interval", "seconds": 30.0}, `^\*HQ,` + imei + `,XT,30#$`, `^XT$`},
		{map[string]any{"text": "S26,0"}, `^\*HQ,` + imei + `,S26,0#$`, `^S26$`},
		{map[string]any{"text": "S26,130305,0"}, `^\*HQ,` + imei + `,S26,130305,0#$`, `^S26,130305$`},
		{map[string]any{"text": "*HQ," + imei + ",INFO#"}, `^\*HQ,` + imei + `,INFO#$`, `^INFO$`},
	}
	times := map[string]bool{}
	for i, cs := range cases {
		f, answers, err := c.Command(imei, cs.content, uint32(i+1))
		if err != nil || !answers {
			t.Fatalf("%v: %v %v", cs.content, err, answers)
		}
		m := regexp.MustCompile(cs.re).FindStringSubmatch(string(f))
		if m == nil {
			t.Fatalf("%v: frame %q", cs.content, f)
		}
		if len(m) > 1 {
			if times[m[1]] {
				t.Fatalf("two commands carry the time %s", m[1])
			}
			times[m[1]] = true
		}
		corr, strict := c.(correlator).Correlation(cs.content, uint32(i+1))
		if !regexp.MustCompile(cs.corr).MatchString(corr) || strict {
			t.Fatalf("%v: correlation %q %v", cs.content, corr, strict)
		}
		if len(m) > 1 && corr != "S20,"+m[1] {
			t.Fatalf("correlation %q does not name the time %s", corr, m[1])
		}
	}
	for _, bad := range []map[string]any{
		{"action": "interval", "seconds": 2.0},    // below 5 s
		{"action": "interval", "seconds": 4000.0}, // above 3600 s
		{"text": "S26#0"},
		{"text": "*HQ,1,CR"},
		{"text": strings.Repeat("x", 201)},
		{"action": "getinfo"},
	} {
		if _, _, err := c.Command(imei, bad, 99); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// profile.namedCommands replaces the text for other firmware (Cantrack R1
// and D1 get the time after the word); "" turns an action off, and the
// action then fails as not supported, saying what to do.
//
// Covers: SIG-IMP-040, SIG-IMP-041
func TestNamedCommandsProfile(t *testing.T) {
	c := codec(t, `{"namedCommands": {"reboot": "R1", "interval": "D1,{seconds}", "locate": ""}, "marker": "TH"}`)
	f, _, err := c.Command(imei, map[string]any{"action": "reboot"}, 1)
	if err != nil || !regexp.MustCompile(`^\*TH,`+imei+`,R1,\d{6}#$`).Match(f) {
		t.Fatalf("reboot %q %v", f, err)
	}
	f, _, err = c.Command(imei, map[string]any{"action": "interval", "seconds": 600.0}, 2)
	if err != nil || !regexp.MustCompile(`^\*TH,`+imei+`,D1,\d{6},600#$`).Match(f) {
		t.Fatalf("interval %q %v", f, err)
	}
	_, _, err = c.Command(imei, map[string]any{"action": "locate"}, 3)
	if !errors.Is(err, track.ErrUnsupported) || !strings.Contains(err.Error(), "namedCommands.locate") {
		t.Fatalf("locate turned off: %v", err)
	}
	for _, bad := range []string{
		`{"namedCommands": {"reboot": "*HQ,1,CQ#"}}`,
		`{"namedCommands": {"reboot": "CQ,{password}"}}`,
		`{"namedCommands": {"dance": "X"}}`,
		`{"answerMatch": "seq"}`,
		`{"alarmBits": {"32": "tamper"}}`,
		`{"marker": "H"}`,
		`{"timezone": "Mars/Base"}`,
		`{"failureWords": [""]}`,
		`{"unknown": 1}`,
	} {
		if _, err := h02.NewCodec(json.RawMessage(bad)); err == nil {
			t.Errorf("profile %s was accepted", bad)
		}
	}
}

// answerMatch: by default an answer is matched by command word and echoed
// time; "command" matches the word only (firmware that does not echo the
// time); "none" leaves matching to the server.
//
// Covers: SIG-IMP-040, SIG-IMP-041
func TestAnswerMatchOption(t *testing.T) {
	noEcho := "*HQ,353505910449999,V4,S20,80,050316,A,2212.8745,N,11346.6574,E,14.28,028,220902,F7FFFBFF#"
	for profile, same := range map[string]bool{``: false, `{"answerMatch": "command"}`: true, `{"answerMatch": "none"}`: true} {
		c := codec(t, profile)
		if _, _, err := c.Command(imei, map[string]any{"action": "engineStop"}, 1); err != nil {
			t.Fatal(err)
		}
		want, _ := c.(correlator).Correlation(nil, 1)
		ms, _ := decode(t, profile, noEcho)
		if got := ms[0].Correlation; (got == want) != same {
			t.Errorf("%q: answer %q, command %q", profile, got, want)
		}
		if ms[0].Records[0].Fix == nil || ms[0].Failed {
			t.Errorf("%q: answer %+v", profile, ms[0])
		}
	}
}

// Status-word polarity, extra and turned-off alarm bits, position
// acknowledgements and the device's time zone are profile settings.
//
// Covers: SIG-IMP-041
func TestStatusAndAckOptions(t *testing.T) {
	v1 := func(w string) string {
		return "*HQ,353505910449999,V1,052825,A,2239.4210,N,11400.8825,E,0.00,348,180814," + w + "#"
	}
	ms, _ := decode(t, `{"statusActiveHigh": true}`, v1("00040400"))
	if got := alertTypes(ms[0].Records[0]); len(got) != 1 || got[0] != "emergency/bit18" || ms[0].Records[0].Status["ignition"] != false {
		t.Fatalf("active high: %v %v", got, ms[0].Records[0].Status)
	}
	ms, _ = decode(t, `{"alarmBits": {"18": "", "26": "tamper"}}`, v1("FBFBFFFF"))
	if got := alertTypes(ms[0].Records[0]); len(got) != 1 || got[0] != "tamper/bit26" {
		t.Fatalf("alarmBits: %v", got)
	}
	ms, _ = decode(t, `{"ackPositions": true, "timezone": "Asia/Kolkata"}`, v1("FFFFFFFF"), hx(bText))
	if !regexp.MustCompile(`^\*HQ,`+imei+`,V4,V1,\d{14}#$`).Match(ms[0].Reply) || !regexp.MustCompile(`^\*HQ,2705171109,R12,\d{6}#$`).Match(ms[1].Reply) {
		t.Fatalf("acks %q %q", ms[0].Reply, ms[1].Reply)
	}
	if h := ms[0].Records[0].Fix.Time; h.Hour() != 23 || h.Minute() != 58 || h.Day() != 17 {
		t.Fatalf("Asia/Kolkata 05:28 is %v UTC", h)
	}
}
