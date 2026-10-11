// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package watch

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// Named commands as watch protocol commands (Communication Protocol
// V1.7_C: CR, RESET, UPLOAD).
var (
	namedDefaults = map[string]string{
		track.ActionLocate:   "CR",
		track.ActionReboot:   "RESET",
		track.ActionInterval: "UPLOAD,{seconds}",
	}
	// Interval bounds the interval command, in seconds.
	Interval = track.IntervalRange{Min: 10, Max: 86400}
	// NamedActions are the named commands watches have: no engine relay.
	NamedActions = []string{track.ActionLocate, track.ActionReboot, track.ActionInterval}
)

func (c *codec) text(imei string, content any) (string, error) {
	n, ok, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if ok {
		return track.NamedText("watch", n, c.cfg.named, namedDefaults, Interval, imei, "")
	}
	if m, isMap := content.(map[string]any); isMap {
		if sos, has := m["sos"]; has {
			list, _ := sos.([]any)
			if len(list) < 1 || len(list) > 3 || len(m) != 1 {
				return "", errors.New(`sos is a list of one to three phone numbers: {"sos": ["…"]}`)
			}
			nums := make([]string, len(list))
			for i, x := range list {
				s, _ := x.(string)
				if strings.ContainsAny(s, ",*[]") {
					return "", fmt.Errorf("sos number %q is not a phone number", s)
				}
				nums[i] = s
			}
			return "SOS," + strings.Join(nums, ","), nil
		}
	}
	return track.CommandText(content)
}

func (c *codec) vendorOut() string {
	switch {
	case c.cfg.vendor != "":
		return c.cfg.vendor
	case c.vendor == "3G":
		return "SG"
	case c.vendor != "":
		return c.vendor
	}
	return "CS"
}

// Command frames a command for the device with ID imei.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	s, err := c.text(imei, content)
	if err != nil {
		return nil, false, err
	}
	if strings.ContainsAny(s, "[]") {
		return nil, false, errors.New("a watch command cannot contain [ or ]")
	}
	index := ""
	if c.hasIndex {
		index = fmt.Sprintf("%04X", seq&0xFFFF)
	}
	// IP,<host>,<port> moves the device to another server: no answer.
	answers := !strings.HasPrefix(strings.ToUpper(s), "IP,")
	return Encode(c.vendorOut(), imei, index, []byte(s)), answers, nil
}

// Correlation: the answer repeats the command's keyword.
func (c *codec) Correlation(content any, _ uint32) (string, bool) {
	s, err := c.text(c.imei, content)
	if err != nil {
		return "", true
	}
	kw, _, _ := strings.Cut(s, ",")
	return strings.ToUpper(strings.TrimSpace(kw)), true
}
