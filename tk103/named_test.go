package tk103_test

import (
	"errors"
	"testing"

	"github.com/cB-Sigma/trackers/tk103"
	"github.com/cB-Sigma/trackers/track"
)

// Named commands are Coban GPRS command letters, sent without waiting for
// an answer (the protocol has none); reboot is not a Coban GPRS command.
//
// Covers: SIG-IMP-008
func TestNamedCommandTexts(t *testing.T) {
	nc, err := tk103.NewCodec(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    map[string]any
		want string
	}{
		{map[string]any{"action": "engineStop"}, "**,imei:" + imei + ",J;"},
		{map[string]any{"action": "engineResume"}, "**,imei:" + imei + ",K;"},
		{map[string]any{"action": "locate"}, "**,imei:" + imei + ",B;"},
		{map[string]any{"action": "interval", "seconds": 30.0}, "**,imei:" + imei + ",C,30s;"},
	} {
		f, answers, err := nc().Command(imei, tc.c, 1)
		if err != nil || answers || string(f) != tc.want {
			t.Errorf("%v: %q %v %v", tc.c, f, answers, err)
		}
	}
	if _, _, err := nc().Command(imei, map[string]any{"action": "reboot"}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Errorf("reboot: %v", err)
	}
}
