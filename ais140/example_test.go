// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ais140_test

import (
	"fmt"

	"github.com/cB-Sigma/trackers/ais140"
	"github.com/cB-Sigma/trackers/track"
)

// Frame a Table 4D command with the device's password: the XOR checksum
// is added, and the answer (an OTA response naming GET 001) is the one the
// codec correlates with it.
func Example() {
	newCodec, err := ais140.NewCodec([]byte(`{"checksum": "xor"}`))
	if err != nil {
		panic(err)
	}
	c := newCodec()
	cmd := map[string]any{"op": "GET", "param": "001"}
	frame, answers, err := c.(track.PasswordCommander).CommandWithPassword("860000000000011", "1234", cmd, 1)
	fmt.Printf("%q %v %v\n", frame, answers, err)
	corr, strict := c.(track.Correlator).Correlation(cmd, 1)
	fmt.Println(corr, strict)
	// Output:
	// "$860000000000011,1234,GET,001*71\r\n" true <nil>
	// GET|1 true
}

func ExampleParseDeviceID() {
	d, err := ais140.ParseDeviceID("SIGM01A092600012345")
	fmt.Println(d.Manufacturer, d.Model, ais140.TestAgencies[d.TestAgency], d.Month, d.Year, d.Serial, err)
	// Output: SIGM 01 Automotive Research Association of India 9 26 00012345 <nil>
}
