package osmand

import (
	"encoding/json"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// NewCodecAt is a codec whose clock reads now.
func NewCodecAt(raw json.RawMessage, now time.Time) (track.Codec, error) {
	mk, err := NewCodec(raw)
	if err != nil {
		return nil, err
	}
	c := mk().(*codec)
	cfg := *c.cfg
	cfg.now = func() time.Time { return now }
	c.cfg = &cfg
	return c, nil
}
