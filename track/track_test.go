// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package track_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// The CRCs give the catalogue check values of "123456789".
func TestCRCCheckValues(t *testing.T) {
	if got := track.CRC16IBM([]byte("123456789")); got != 0xBB3D {
		t.Errorf("CRC-16/ARC %04X", got)
	}
	if got := track.CRCITU([]byte("123456789")); got != 0x906E {
		t.Errorf("CRC-16/X-25 %04X", got)
	}
}

func TestSeverities(t *testing.T) {
	for typ, want := range map[string]string{"emergency": track.Critical, "tamper": track.Major, "over-speed": track.Minor,
		"ignition-on": track.Info, "something-new": track.Minor} {
		if got := track.SeverityOf(typ); got != want {
			t.Errorf("%s: %s, want %s", typ, got, want)
		}
	}
	if a := track.NewAlert("emergency", "0x01"); a.Severity != track.Critical || a.Code != "0x01" {
		t.Errorf("%+v", a)
	}
}

func TestReadNamed(t *testing.T) {
	n, ok, err := track.ReadNamed(map[string]any{"action": "interval", "seconds": 30.0})
	if !ok || err != nil || n.Action != track.ActionInterval || n.Seconds != 30 {
		t.Fatalf("%+v %v %v", n, ok, err)
	}
	if _, ok, _ := track.ReadNamed(map[string]any{"text": "WHERE#"}); ok {
		t.Error("a text command read as named")
	}
	for _, bad := range []map[string]any{
		{"action": "selfDestruct"},
		{"action": "interval"},
		{"action": "interval", "seconds": 1.5},
		{"action": "locate", "force": true},
		{"action": "reboot", "seconds": 3.0},
		{"action": "engineStop", "extra": 1.0},
	} {
		if _, ok, err := track.ReadNamed(bad); !ok || err == nil {
			t.Errorf("%v: ok %v, err %v", bad, ok, err)
		}
	}
}

func TestNamedTemplates(t *testing.T) {
	tm := track.NamedTemplates{"interval": "TIMER,{seconds}#", "engineStop": "DYD,{password}#", "reboot": ""}
	if err := tm.Check(true); err != nil {
		t.Fatal(err)
	}
	if err := tm.Check(false); err == nil || !strings.Contains(err.Error(), "{password}") {
		t.Errorf("password placeholder without passwords: %v", err)
	}
	for _, bad := range []track.NamedTemplates{{"dance": "X"}, {"locate": "{where}"}, {"locate": "W{seconds}"}} {
		if err := bad.Check(true); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	iv := track.IntervalRange{Min: 10, Max: 100}
	got, err := track.NamedText("demo", track.Named{Action: "interval", Seconds: 30}, tm, nil, iv, "123", "")
	if err != nil || got != "TIMER,30#" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := track.NamedText("demo", track.Named{Action: "interval", Seconds: 5}, tm, nil, iv, "123", ""); err == nil {
		t.Error("interval below the range accepted")
	}
	if _, err := track.NamedText("demo", track.Named{Action: "reboot"}, tm, map[string]string{"reboot": "RESET#"}, iv, "123", ""); !errors.Is(err, track.ErrUnsupported) {
		t.Errorf("a template turned off: %v", err)
	}
	if _, err := track.NamedText("demo", track.Named{Action: "engineStop"}, tm, nil, iv, "123", ""); err == nil {
		t.Error("{password} without a password accepted")
	}
}

func TestDurationAndStrictJSON(t *testing.T) {
	var p struct {
		Every track.Duration `json:"every"`
	}
	if err := track.StrictJSON([]byte(`{"every": "90s"}`), &p); err != nil || p.Every.D() != 90*time.Second {
		t.Fatalf("%v %v", p.Every.D(), err)
	}
	if err := track.StrictJSON([]byte(`{"every": 2}`), &p); err != nil || p.Every.D() != 2*time.Second {
		t.Fatalf("%v %v", p.Every.D(), err)
	}
	if err := track.StrictJSON([]byte(`{"every": "soon"}`), &p); err == nil {
		t.Error("a bad duration accepted")
	}
	if err := track.StrictJSON([]byte(`{"evry": "1s"}`), &p); err == nil {
		t.Error("an unknown key accepted")
	}
	if b, _ := json.Marshal(p.Every); string(b) != `"2s"` {
		t.Errorf("%s", b)
	}
}

func TestFailureWords(t *testing.T) {
	w, err := track.FailureWords(nil, "error", "fail")
	if err != nil || !track.AnswerFailed("Command ERROR!", w) || track.AnswerFailed("OK", w) {
		t.Fatalf("%v %v", w, err)
	}
	if _, err := track.FailureWords([]string{" "}); err == nil {
		t.Error("a blank word accepted")
	}
}

func TestSkipIsErrSkip(t *testing.T) {
	var err error = &track.Skip{Warning: track.Warning{Code: "unknownMessage", Msg: "passed over"}}
	if !errors.Is(err, track.ErrSkip) || !strings.Contains(err.Error(), "passed over") {
		t.Fatal(err)
	}
}

// A named command, as an application sends it, becomes a protocol's text.
func ExampleNamedText() {
	n, _, err := track.ReadNamed(map[string]any{"action": "interval", "seconds": 60.0})
	if err != nil {
		panic(err)
	}
	defaults := map[string]string{track.ActionInterval: "TIMER,{seconds}#"}
	text, err := track.NamedText("gt06", n, nil, defaults, track.IntervalRange{Min: 10, Max: 18000}, "359710049099999", "")
	fmt.Println(text, err)
	// Output: TIMER,60# <nil>
}
