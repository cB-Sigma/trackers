// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package atrack_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cB-Sigma/trackers/atrack"
	"github.com/cB-Sigma/trackers/track"
)

const imei = "352964052096642"

// Commands are AT$ text lines ending CR LF; the sequence becomes the
// command's tag, which the answer repeats and the codec correlates.
func TestCommandText(t *testing.T) {
	c := codec(t, "")
	for _, tc := range []struct {
		content any
		want    string
		answers bool
		corr    string
	}{
		{map[string]any{"text": "AT$INFO=?"}, "AT$INFO+42=?\r\n", true, "42"},
		{"AT$TRAC=1,30", "AT$TRAC+42=1,30\r\n", true, "42"},
		{"AT$GPOS", "AT$GPOS+42\r\n", false, "42"},
		{"AT$INFO+ab=?", "AT$INFO+ab=?\r\n", true, "ab"},
		{"ATZ", "ATZ\r\n", true, ""},
		{map[string]any{"action": "reboot"}, "AT$REST+42=1,0\r\n", true, "42"},
		{map[string]any{"action": "locate"}, "AT$GPOS+42\r\n", false, "42"},
		{map[string]any{"action": "engineStop"}, "AT$OUTC+42=1,1\r\n", true, "42"},
		{map[string]any{"action": "engineResume"}, "AT$OUTC+42=1,0\r\n", true, "42"},
		{map[string]any{"action": "interval", "seconds": 60}, "AT$TRAC+42=1,60\r\n", true, "42"},
	} {
		f, answers, err := c.Command(imei, tc.content, 42)
		if err != nil || string(f) != tc.want || answers != tc.answers {
			t.Errorf("%v: %q %v %v", tc.content, f, answers, err)
		}
		corr, strict := c.(track.Correlator).Correlation(tc.content, 42)
		if corr != tc.corr || strict {
			t.Errorf("%v: correlation %q %v", tc.content, corr, strict)
		}
	}
	// Tags are at most five characters: the sequence modulo 100000.
	if f, _, _ := c.Command(imei, "AT$INFO=?", 1234567); string(f) != "AT$INFO+34567=?\r\n" {
		t.Errorf("%q", f)
	}
	if _, _, err := c.Command(imei, map[string]any{"action": "interval", "seconds": 0.5}, 1); err == nil {
		t.Error("half a second accepted")
	}
	if _, _, err := c.Command(imei, "AT$X=1\r\nAT$REST=1", 1); err == nil {
		t.Error("a line break inside a command accepted")
	}
}

// commandTag false sends commands as written and correlates nothing.
func TestCommandTagOff(t *testing.T) {
	c := codec(t, `{"commandTag": false}`)
	f, _, err := c.Command(imei, map[string]any{"action": "reboot"}, 42)
	if err != nil || string(f) != "AT$REST=1,0\r\n" {
		t.Fatalf("%q %v", f, err)
	}
	if corr, _ := c.(track.Correlator).Correlation("AT$INFO=?", 42); corr != "" {
		t.Fatalf("%q", corr)
	}
}

// The device's command password goes before the parameters of named
// commands, from the profile or CommandWithPassword.
func TestCommandPassword(t *testing.T) {
	c := codec(t, `{"commandPassword": "1234"}`)
	f, _, err := c.Command(imei, map[string]any{"action": "engineStop"}, 3)
	if err != nil || string(f) != "AT$OUTC+3=1234,1,1\r\n" {
		t.Fatalf("%q %v", f, err)
	}
	pc := c.(track.PasswordCommander)
	f, _, err = pc.CommandWithPassword(imei, "9999", map[string]any{"action": "interval", "seconds": 30}, 3)
	if err != nil || string(f) != "AT$TRAC+3=9999,1,30\r\n" {
		t.Fatalf("%q %v", f, err)
	}
	f, _, err = pc.CommandWithPassword(imei, "", map[string]any{"action": "locate"}, 3)
	if err != nil || string(f) != "AT$GPOS+3=1234\r\n" {
		t.Fatalf("%q %v", f, err)
	}
}

// namedCommands replaces a named command; "" turns it off.
func TestNamedCommandsProfile(t *testing.T) {
	c := codec(t, `{"namedCommands": {"engineStop": "AT$OUTC=2,1,0,0,0,10", "reboot": ""}}`)
	f, _, err := c.Command(imei, map[string]any{"action": "engineStop"}, 1)
	if err != nil || string(f) != "AT$OUTC+1=2,1,0,0,0,10\r\n" {
		t.Fatalf("%q %v", f, err)
	}
	if _, _, err := c.Command(imei, map[string]any{"action": "reboot"}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Fatalf("%v", err)
	}
	for _, p := range []string{`{"namedCommands": {"fly": "x"}}`, `{"form": "MV"}`, `{"bogus": 1}`} {
		if _, err := atrack.NewCodec(json.RawMessage(p)); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
