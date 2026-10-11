package track

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Table-driven CRCs (bit-reflected); built once.
var (
	itu = table(0x8408) // CRC-16/X-25 ("CRC-ITU" in tracker documents)
	ibm = table(0xA001) // CRC-16/ARC ("CRC-16/IBM")
)

func table(poly uint16) *[256]uint16 {
	var t [256]uint16
	for i := range t {
		c := uint16(i)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ poly
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return &t
}

// CRCITU is CRC-16/X-25: reflected 0x1021, init and final XOR 0xFFFF.
func CRCITU(b []byte) uint16 {
	c := uint16(0xFFFF)
	for _, v := range b {
		c = c>>8 ^ itu[byte(c)^v]
	}
	return c ^ 0xFFFF
}

// CRC16IBM is CRC-16/ARC: reflected 0x8005, init 0, no final XOR.
func CRC16IBM(b []byte) uint16 {
	var c uint16
	for _, v := range b {
		c = c>>8 ^ ibm[byte(c)^v]
	}
	return c
}

// Alert types every tracker protocol maps to, with their severities.
var severities = map[string]string{
	"emergency":            Critical,
	"main-power-removed":   Major,
	"tamper":               Major,
	"box-opened":           Major,
	"emergency-wire-cut":   Major,
	"impact":               Major,
	"towing":               Major,
	"gnss-jamming":         Major,
	"gsm-jamming":          Major,
	"gnss-antenna-cut":     Major,
	"theft":                Major,
	"vehicle-theft":        Major,
	"fuel-theft":           Major,
	"rollover":             Major,
	"illegal-ignition":     Major,
	"door-open":            Minor,
	"fatigue-driving":      Minor,
	"harsh-braking":        Minor,
	"harsh-acceleration":   Minor,
	"rash-turning":         Minor,
	"over-speed":           Minor,
	"low-battery":          Minor,
	"vibration":            Minor,
	"geofence-exit":        Minor,
	"tilt":                 Minor,
	"emergency-off":        Info,
	"main-power-restored":  Info,
	"low-battery-restored": Info,
	"ignition-on":          Info,
	"ignition-off":         Info,
	"geofence-enter":       Info,
	"ota-parameter-change": Info,
	"ota-unknown-source":   Major,
	"trailer-changed":      Major,
	"trailer-mismatch":     Major,
	"trailer-unpaired":     Minor,
	"trailer-paired":       Info,
	"health-check-missed":  Minor,
	"sim-inactive":         Major,
	"sim-kyc-pending":      Minor,
	"sim-expiring":         Minor,
}

// SeverityOf is the severity of an alert type: critical, major, minor or
// info (unknown types are minor).
func SeverityOf(typ string) string {
	if s, ok := severities[typ]; ok {
		return s
	}
	return Minor
}

// NewAlert is an alert of a known type with its severity.
func NewAlert(typ, code string) Alert {
	return Alert{Type: typ, Severity: SeverityOf(typ), Code: code}
}

// StrictJSON decodes a profile, refusing unknown keys.
func StrictJSON(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// F and I return pointers, for optional Fix fields.
func F(v float64) *float64 { return &v }

// I returns a pointer to v.
func I(v int) *int { return &v }

// FailureWords checks a profile's failureWords: the words (any case) whose
// presence in a device's command answer marks the command failed. Empty
// keeps def, the protocol's default list; words must not be blank.
func FailureWords(words []string, def ...string) ([]string, error) {
	if len(words) == 0 {
		return def, nil
	}
	out := make([]string, 0, len(words))
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			return nil, errors.New("failureWords: a word must not be empty")
		}
		out = append(out, w)
	}
	return out, nil
}

// AnswerFailed reports whether a command answer holds one of the failure
// words (lower case).
func AnswerFailed(text string, words []string) bool {
	t := strings.ToLower(text)
	for _, w := range words {
		if strings.Contains(t, w) {
			return true
		}
	}
	return false
}
