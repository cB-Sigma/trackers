// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ais140_test

import (
	"encoding/json"

	"github.com/cB-Sigma/trackers/ais140"
	"github.com/cB-Sigma/trackers/track"
)

// device is what a command needs to know of the device.
type device struct{ IMEI, CommandPassword string }

// parseForTest parses one packet with a profile.
func parseForTest(profile, text, sum string) (any, error) {
	c, err := ais140.ParseProfile(json.RawMessage(profile))
	if err != nil {
		return nil, err
	}
	return c.Parse(text, sum)
}

// commandForTest frames a command for a device with a profile.
func commandForTest(profile string, dc *device, content any) ([]byte, bool, error) {
	nc, err := ais140.NewCodec(json.RawMessage(profile))
	if err != nil {
		return nil, false, err
	}
	return nc().(track.PasswordCommander).CommandWithPassword(dc.IMEI, dc.CommandPassword, content, 1)
}
