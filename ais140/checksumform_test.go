package ais140_test

import (
	"bufio"
	"strings"
	"testing"

	"github.com/cB-Sigma/trackers/ais140"
)

// A command's XOR checksum is computed the way the device computes its
// own: without the '$' by default and for a device whose packets do so,
// with it for a device whose packets include it.
//
// Covers: SIG-CMD-012
func TestCommandChecksumFollowsDevice(t *testing.T) {
	body := "LGN,KA01F1234," + imei + ",89910000000000000013,01.01.01,0100,12.974512,N,77.614563,E"
	without := "$" + body + "*" + xorChecksum(body)
	with := "$" + body + "*" + xorChecksum("$"+body)
	cmdBody := imei + ",1234,GET,013"
	for name, tc := range map[string]struct {
		pkt, want string
	}{
		"none seen": {"", xorChecksum(cmdBody)},
		"without $": {without, xorChecksum(cmdBody)},
		"with $":    {with, xorChecksum("$" + cmdBody)},
	} {
		nc, err := ais140.NewCodec(nil)
		if err != nil {
			t.Fatal(err)
		}
		c := nc()
		if tc.pkt != "" {
			if _, err := c.Decode(bufio.NewReader(strings.NewReader(tc.pkt + "\r\n"))); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		f, _, err := c.(interface {
			CommandWithPassword(string, string, any, uint32) ([]byte, bool, error)
		}).CommandWithPassword(imei, "1234", map[string]any{"op": "GET", "param": "013"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(f); got != "$"+cmdBody+"*"+tc.want+"\r\n" {
			t.Errorf("%s: %q, want checksum %s", name, got, tc.want)
		}
	}
}
