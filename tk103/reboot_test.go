// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tk103_test

import (
	"encoding/json"
	"testing"

	"github.com/cB-Sigma/trackers/tk103"
)

// No public GPS103/Coban document gives a reboot over GPRS, so reboot has
// no default; firmware that has one gets it from the profile's template.
func TestRebootByProfileTemplate(t *testing.T) {
	nc, err := tk103.NewCodec(json.RawMessage(`{"namedCommands": {"reboot": "REBOOT"}}`))
	if err != nil {
		t.Fatal(err)
	}
	f, answers, err := nc().Command(imei, map[string]any{"action": "reboot"}, 1)
	if err != nil || answers || string(f) != "**,imei:"+imei+",REBOOT;" {
		t.Fatalf("%q %v %v", f, answers, err)
	}
	for _, a := range tk103.NamedActions {
		if a == "reboot" {
			t.Fatal("reboot is listed as a default named action")
		}
	}
}
