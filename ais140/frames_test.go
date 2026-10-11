// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ais140_test

import "fmt"

// xorChecksum is the two-hex-digit XOR checksum a packet ends with. The
// tests build frames themselves, so the library does not depend on its
// simulator (github.com/cB-Sigma/trackers-sim).
func xorChecksum(s string) string {
	var x byte
	for i := 0; i < len(s); i++ {
		x ^= s[i]
	}
	return fmt.Sprintf("%02X", x)
}
