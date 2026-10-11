package tk103_test

import (
	"encoding/json"
	"testing"

	"github.com/cB-Sigma/trackers/tk103"
)

// A command ends with ';' by default; commandTerminator "" sends it
// without, as some firmware wants.
//
// Covers: SIG-CMD-011
func TestCommandTerminatorOption(t *testing.T) {
	for profile, want := range map[string]string{
		``:                           "**,imei:" + imei + ",B;",
		`{"commandTerminator": ";"}`: "**,imei:" + imei + ",B;",
		`{"commandTerminator": ""}`:  "**,imei:" + imei + ",B",
	} {
		nc, err := tk103.NewCodec(json.RawMessage(profile))
		if err != nil {
			t.Fatal(err)
		}
		f, answers, err := nc().Command(imei, map[string]any{"text": "B"}, 1)
		if err != nil || answers || string(f) != want {
			t.Errorf("%q: %q %v %v", profile, f, answers, err)
		}
	}
	if _, err := tk103.NewCodec(json.RawMessage(`{"commandTerminator": "#"}`)); err == nil {
		t.Fatal("terminator # accepted")
	}
}
