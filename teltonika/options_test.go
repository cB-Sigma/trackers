package teltonika_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cB-Sigma/trackers/teltonika"
)

// The words that fail a Codec 12 answer are a profile setting; the default
// is error, unknown and fail.
//
// Covers: SIG-CMD-013
func TestFailureWordsOption(t *testing.T) {
	for profile, failed := range map[string]bool{``: true, `{"failureWords": ["error"]}`: false} {
		nc, err := teltonika.NewCodec(json.RawMessage(profile))
		if err != nil {
			t.Fatal(err)
		}
		c := nc()
		br := bufio.NewReader(bytes.NewReader(append(h(vHandshake), teltonika.Codec12Frame(teltonika.TypeResp, "Param ID:1000 unknown value")...)))
		if _, err := c.Decode(br); err != nil {
			t.Fatal(err)
		}
		m, err := c.Decode(br)
		if err != nil || m.Response == nil || m.Failed != failed {
			t.Errorf("%q: %+v %v", profile, m, err)
		}
	}
}
