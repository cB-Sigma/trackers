// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package jt808_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/jt808"
	"github.com/cB-Sigma/trackers/track"
)

// commandFrame frames content with a fresh codec of profile that has
// heard the 2013 or 2019 location vector first.
func commandFrame(t *testing.T, profile string, v2019 bool, content any, seq uint32) (*jt808.Frame, error) {
	t.Helper()
	c := codec(t, profile)
	v := vLocation
	if v2019 {
		v = vBatch2019
	}
	decodeAll(t, c, v)
	b, answers, err := c.Command("x", content, seq)
	if err != nil {
		return nil, err
	}
	if !answers {
		t.Fatal("a JT808 command without an answer")
	}
	return frameOf(t, b), nil
}

// The named commands' bytes: 0x8500 control flag 1/0 (2013) and the 2019
// control item, 0x8201, 0x8105 command 4, 0x8103 parameter 0x0029, text
// as 0x8300 (flag, and the 2019 text type) or 0x8900 type 0xF0, and the
// engineControl variants.
//
// Covers: SIG-IMP-035
func TestCommandBytes(t *testing.T) {
	for _, c := range []struct {
		profile string
		v2019   bool
		content map[string]any
		id      uint16
		body    []byte
	}{
		{"", false, map[string]any{"action": "engineStop"}, 0x8500, []byte{1}},
		{"", false, map[string]any{"action": "engineResume"}, 0x8500, []byte{0}},
		{"", true, map[string]any{"action": "engineStop"}, 0x8500, []byte{0, 1, 0, 1, 1}},
		{"", false, map[string]any{"action": "locate"}, 0x8201, nil},
		{"", false, map[string]any{"action": "reboot"}, 0x8105, []byte{4}},
		{"", false, map[string]any{"action": "interval", "seconds": 30}, 0x8103, []byte{1, 0, 0, 0, 0x29, 4, 0, 0, 0, 30}},
		{"", false, map[string]any{"text": "WHERE#"}, 0x8300, append([]byte{1}, "WHERE#"...)},
		{"", true, map[string]any{"text": "WHERE#"}, 0x8300, append([]byte{1, 1}, "WHERE#"...)},
		{`{"textFlag": 0}`, false, map[string]any{"text": "WHERE#"}, 0x8300, append([]byte{0}, "WHERE#"...)},
		{`{"textCommand": "8900"}`, false, map[string]any{"text": "WHERE#"}, 0x8900, append([]byte{0xF0}, "WHERE#"...)},
		{`{"engineControl": "text"}`, false, map[string]any{"action": "engineStop"}, 0x8300, append([]byte{1}, "RELAY,1#"...)},
		{`{"engineControl": "text"}`, false, map[string]any{"action": "engineResume"}, 0x8300, append([]byte{1}, "RELAY,0#"...)},
		{`{"engineControl": "terminalControl"}`, false, map[string]any{"action": "engineStop"}, 0x8105, []byte{0xF0}},
		{`{"namedCommands": {"reboot": "RESET#"}}`, false, map[string]any{"action": "reboot"}, 0x8300, append([]byte{1}, "RESET#"...)},
		{`{"namedCommands": {"interval": "TIMER,{seconds}#"}}`, false, map[string]any{"action": "interval", "seconds": 60}, 0x8300, append([]byte{1}, "TIMER,60#"...)},
	} {
		f, err := commandFrame(t, c.profile, c.v2019, c.content, 0x1234)
		if err != nil {
			t.Errorf("%s %v: %v", c.profile, c.content, err)
			continue
		}
		if f.ID != c.id || f.Serial != 0x1234 || !bytes.Equal(f.Body, c.body) || f.V2019() != c.v2019 {
			t.Errorf("%s %v: 0x%04X serial %d % X (2019 %v)", c.profile, c.content, f.ID, f.Serial, f.Body, f.V2019())
		}
	}
	// Refused before anything is sent.
	for profile, content := range map[string]map[string]any{
		``:                                       {"action": "interval", "seconds": 0},
		` `:                                      {"text": "RELAY,1#é"},
		`  `:                                     {"text": strings.Repeat("x", 1001)},
		`{"namedCommands": {"locate": ""}}`:      {"action": "locate"},
		`{"namedCommands": {"interval": "T#"}} `: {"action": "interval", "seconds": 100000},
		`   `:                                    {"action": "getinfo"},
	} {
		if _, err := commandFrame(t, strings.TrimSpace(profile), false, content, 1); err == nil {
			t.Errorf("%v was framed", content)
		}
	}
	_, err := commandFrame(t, `{"namedCommands": {"locate": ""}}`, false, map[string]any{"action": "locate"}, 1)
	if !errors.Is(err, track.ErrUnsupported) {
		t.Errorf("a turned-off named command: %v", err)
	}
}
