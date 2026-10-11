// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gt06_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/cB-Sigma/trackers/gt06"
)

// Decode a login frame and frame a named command for the device.
func Example() {
	newCodec, err := gt06.NewCodec(nil) // the default profile
	if err != nil {
		panic(err)
	}
	c := newCodec() // one per connection
	login, _ := hex.DecodeString("78780D01012345678901234500018CDD0D0A")
	m, err := c.Decode(bufio.NewReader(bytes.NewReader(login)))
	if err != nil {
		panic(err)
	}
	fmt.Println(m.IMEI, m.Login, hex.EncodeToString(m.Reply))
	frame, answers, err := c.Command(m.IMEI, map[string]any{"action": "locate"}, 7)
	fmt.Println(hex.EncodeToString(frame), answers, err)
	// Output:
	// 123456789012345 true 787805010001d9dc0d0a
	// 787812800a000000075748455245230002000766ab0d0a true <nil>
}
