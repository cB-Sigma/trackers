// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package suntech_test

import (
	"bufio"
	"errors"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/suntech"
	"github.com/cB-Sigma/trackers/track"
)

// after is a codec that has read frame (so it knows the device's format
// and model).
func after(t *testing.T, profile, frame string) track.Codec {
	t.Helper()
	nc, err := suntech.NewCodec([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	if frame != "" {
		if _, err := c.Decode(bufio.NewReader(strings.NewReader(frame + "\r"))); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestNamedCommands(t *testing.T) {
	legacy := after(t, "", st300STT)
	universal := after(t, "", uniSTT)
	for _, tc := range []struct {
		c          track.Codec
		id, action string
		want, corr string
	}{
		{legacy, "007238270", "engineStop", "ST300CMD;007238270;02;Enable1\r", "Enable1"},
		{legacy, "007238270", "engineResume", "ST300CMD;007238270;02;Disable1\r", "Disable1"},
		{legacy, "007238270", "locate", "ST300CMD;007238270;02;StatusReq\r", "StatusReq"},
		{legacy, "007238270", "reboot", "ST300CMD;007238270;02;Reboot\r", "Reboot"},
		{universal, "0560001616", "engineStop", "CMD;0560001616;04;01\r", "04;01"},
		{universal, "0560001616", "engineResume", "CMD;0560001616;04;02\r", "04;02"},
		{universal, "0560001616", "locate", "CMD;0560001616;03;01\r", "03;01"},
		{universal, "0560001616", "reboot", "CMD;0560001616;03;03\r", "03;03"},
	} {
		content := map[string]any{"action": tc.action}
		f, answers, err := tc.c.Command(tc.id, content, 1)
		if err != nil || !answers || string(f) != tc.want {
			t.Errorf("%s: %q %v %v", tc.want, f, answers, err)
		}
		corr, strict := tc.c.(track.Correlator).Correlation(content, 1)
		if corr != tc.corr || !strict {
			t.Errorf("%s: correlation %q %v", tc.want, corr, strict)
		}
	}
	for _, c := range []track.Codec{legacy, universal} {
		if _, _, err := c.Command("1", map[string]any{"action": "interval", "seconds": 60.0}, 1); !errors.Is(err, track.ErrUnsupported) {
			t.Errorf("interval: %v", err)
		}
	}
}

// Before the first report the codec does not know the device's format:
// the profile says it, or the command fails with the reason.
func TestCommandFormatFromProfile(t *testing.T) {
	stop := map[string]any{"action": "engineStop"}
	if _, _, err := after(t, "", "").Command("123", stop, 1); err == nil || !strings.Contains(err.Error(), "profile.format") {
		t.Errorf("unknown format: %v", err)
	}
	for profile, want := range map[string]string{
		`{"format": "universal"}`:                "CMD;123;04;01\r",
		`{"format": "legacy", "model": "SA200"}`: "SA200CMD;123;02;Enable1\r",
		`{"model": "ST340"}`:                     "ST340CMD;123;02;Enable1\r",
	} {
		f, _, err := after(t, profile, "").Command("123", stop, 1)
		if err != nil || string(f) != want {
			t.Errorf("%s: %q %v", profile, f, err)
		}
	}
	if _, err := suntech.NewCodec([]byte(`{"format": "legacy"}`)); err == nil {
		t.Error("legacy without model accepted")
	}
}

func TestTextCommandsAndTemplates(t *testing.T) {
	c := after(t, `{"namedCommands": {"interval": "ST300RPT;{imei};02;{seconds}", "reboot": ""}}`, st300STT)
	f, answers, err := c.Command("007238270", map[string]any{"action": "interval", "seconds": 120.0}, 1)
	if err != nil || !answers || string(f) != "ST300RPT;007238270;02;120\r" {
		t.Errorf("interval template: %q %v", f, err)
	}
	if _, _, err := c.Command("007238270", map[string]any{"action": "reboot"}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Errorf("reboot turned off: %v", err)
	}
	for text, want := range map[string]string{
		"ST300CMD;007238270;02;Enable2":    "ST300CMD;007238270;02;Enable2\r",
		"CMD;0560001616;04;03\r":           "CMD;0560001616;04;03\r",
		"ST300CMD;007238270;02;Preset\r\n": "",
	} {
		f, _, err := c.Command("007238270", map[string]any{"text": text}, 1)
		if want == "" {
			if err == nil {
				t.Errorf("%q accepted", text)
			}
			continue
		}
		if err != nil || string(f) != want {
			t.Errorf("%q: %q %v", text, f, err)
		}
	}
	cr := c.(track.Correlator)
	for text, want := range map[string]string{
		"ST300CMD;007238270;02;Enable2": "Enable2",
		"CMD;0560001616;04;03":          "04;03",
		"ST300RPT;007238270;02;60":      "",
	} {
		if corr, _ := cr.Correlation(map[string]any{"text": text}, 1); corr != want {
			t.Errorf("%q: correlation %q", text, corr)
		}
	}
}

// An answer naming an error fails its command.
func TestFailedAnswer(t *testing.T) {
	m := one(t, "ST300CMD;Res;511848119;319H;Enable1;Error")
	if !m.Failed || m.Correlation != "Enable1" {
		t.Errorf("%+v", m)
	}
}
