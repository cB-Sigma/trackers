package queclink

import (
	"encoding/json"

	"github.com/cB-Sigma/trackers/track"
)

// NewCodecForTest builds a codec whose command serials start after base.
func NewCodecForTest(profile string, base uint32) (track.Codec, error) {
	nc, err := NewCodec(json.RawMessage(profile))
	if err != nil {
		return nil, err
	}
	c := nc().(*codec)
	c.base = base
	return c, nil
}
