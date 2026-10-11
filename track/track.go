// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package track holds what every tracker protocol of this module shares:
// the decoded report (Fix, Alert, Record, Message), the radio networks a
// device heard (Network, Cell, WiFiAP), the Codec interface each protocol
// implements, the optional interfaces a server looks for (Correlator,
// DatagramCodec, DatagramCommander, PasswordCommander, SMSRequester),
// named commands that mean the same on every protocol (Named, ReadNamed,
// NamedTemplates), alert types with their severities, and the CRCs the
// binary protocols use.
//
// A server reads frames from a connection with Codec.Decode, sends
// Message.Reply back, and frames commands with Codec.Command. Sessions,
// device lists, queues and storage are the server's business; this
// package and the protocol packages do no I/O of their own beyond the
// reader they are given, keep no state outside a codec, and never log.
package track

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Severities of alerts.
const (
	Critical = "critical"
	Major    = "major"
	Minor    = "minor"
	Info     = "info"
)

// Fix is one position report.
type Fix struct {
	Time     time.Time
	Lat, Lon float64
	Valid    bool     // the receiver had a fix
	Alt      *float64 // metres
	Speed    *float64 // km/h
	Heading  *float64 // degrees from north
	Sats     *int
	HDOP     *float64
}

// Alert is an event the device reported.
type Alert struct {
	Type     string // our name: "emergency", "main-power-removed", "harsh-braking", …
	Severity string
	Code     string // the protocol's own code, when there is one
}

// Record is one report: a position, status values and alerts, any of which
// may be absent.
type Record struct {
	Fix     *Fix
	Status  map[string]any
	Alerts  []Alert
	History bool // stored on the device and sent late
	Time    time.Time
	// Network is the cells and WiFi access points the device reported.
	Network *Network
	// Trailer is the trailer tag the device read ("" none), when the
	// protocol reports one (AIS-140 RFID trackers).
	Trailer *string
}

// Message is what a codec decoded from one frame.
type Message struct {
	// IMEI identifies the device; codecs set it on every frame that
	// carries it (a login at least).
	IMEI   string
	Login  bool
	Secret string // a password the login carried, if the protocol has one
	// Raw is the packet as received, for forwarding (codecs that keep it).
	Raw []byte
	// Records are the reports in the frame.
	Records []Record
	// Reply is sent to the device once the frame is accepted; Reject is
	// sent instead when the IMEI is refused (then the connection closes).
	Reply, Reject []byte
	// Response is the device's answer to a command; Failed marks an
	// answer that says the command failed. Details, when set, go into the
	// command's result.
	Response *string
	Failed   bool
	Details  map[string]any
	// Correlation names the command an answer is to, when the protocol's
	// answers carry that (the server flag of a GT06 answer, the operation
	// and keys of an AIS-140 OTA response); "" when it does not. See
	// Correlator.
	Correlation string
	// Kind names the packet kind (login, normal, health, emergency,
	// response), for forward filters and logs.
	Kind string
	// ICCID is the SIM a login named.
	ICCID string
	// ReplyKind and ReplyCode identify the device's answer to an SMS
	// request (SMSRequester).
	ReplyKind, ReplyCode string
	// Warnings are what the codec accepted from a device that deviates
	// from its protocol (a variant IMEI form, an unknown field).
	Warnings []Warning
}

// Warning is a deviation a codec accepted. Code is a short camel-case name
// ("imeiFormat"); Setting the dotted profile path that changes the
// behaviour, if any.
type Warning struct {
	Code, Setting, Msg, Detail string
}

// Skip is an ErrSkip with a reason the operator should see: the frame is
// passed over (the session reads on) and the reason is a warning against
// the device.
type Skip struct {
	Warning
	// Reply, when set, is sent to the device before reading on (an HTTP
	// codec's 401 to a request without its token).
	Reply []byte
}

// Error says the frame was skipped, and why.
func (s *Skip) Error() string { return "frame skipped: " + s.Msg }

// Is makes a Skip an ErrSkip.
func (s *Skip) Is(target error) bool { return target == ErrSkip }

// ErrSkip is returned by Decode for a frame that carries nothing (noise
// the codec resynchronised over); the session reads on.
var ErrSkip = errors.New("frame skipped")

// Codec is one connection's protocol state.
type Codec interface {
	// Decode reads the next frame. io.EOF ends the session; ErrSkip reads
	// on; any other error closes the connection.
	Decode(r *bufio.Reader) (*Message, error)
	// Command encodes a command for the device and reports whether the
	// device answers it. content is the command as decoded from JSON: a
	// string, {"text": …}, a named command ({"action": …}) or a
	// protocol's own form.
	Command(imei string, content any, seq uint32) (frame []byte, answers bool, err error)
}

// NewCodec is what each protocol package exports: it validates a profile
// (the protocol's JSON settings; empty for the defaults) and returns a
// factory of codecs, one per connection.
type NewCodec func(profile json.RawMessage) (func() Codec, error)

// DatagramCodec is implemented by codecs whose UDP framing differs from
// their TCP framing (Teltonika).
type DatagramCodec interface {
	DecodeDatagram(b []byte) ([]*Message, error)
}

// DatagramCommander is implemented by codecs with their own UDP framing
// (DatagramCodec) that can also frame commands for UDP. A DatagramCodec
// without it takes commands over TCP only, since its TCP command framing
// would not be understood in a datagram.
type DatagramCommander interface {
	DatagramCommands() bool
}

// Correlator is implemented by codecs whose command answers name the
// command they answer: Correlation is the Message.Correlation of the
// answer to this command ("" when its answer names none). With strict an
// answer that names no command is not this command's; without it (a
// device may not echo the name) it is taken.
type Correlator interface {
	Correlation(content any, seq uint32) (corr string, strict bool)
}

// PasswordCommander is implemented by codecs whose commands carry the
// device's command password (AIS-140, Queclink, Ruptela). Command is then
// CommandWithPassword with no password: the profile's, if it has one.
type PasswordCommander interface {
	CommandWithPassword(imei, password string, content any, seq uint32) (frame []byte, answers bool, err error)
}

// SMSRequester is a codec whose commands may be requests sent to the
// device by SMS rather than over its connection: it returns the request
// kind ("HCHK") for such a command.
type SMSRequester interface {
	SMSRequest(content any) (kind string, ok bool)
}

// Network is what a tracker reported about the radio networks around it.
type Network struct {
	Cells []Cell
	WiFi  []WiFiAP
	// TA is the GSM timing advance, when reported.
	TA *int
}

// Cell is one mobile cell. RSSI is in dBm (nil when not reported).
type Cell struct {
	MCC, MNC, LAC int
	CID           int64
	RSSI          *int
}

// WiFiAP is one WiFi access point: MAC as aa:bb:cc:dd:ee:ff, RSSI in dBm.
type WiFiAP struct {
	MAC  string
	RSSI *int
}

// CommandText reads the common command forms: a string, or {"text": "…"}.
func CommandText(content any) (string, error) {
	switch c := content.(type) {
	case string:
		if c != "" {
			return c, nil
		}
	case map[string]any:
		if s, ok := c["text"].(string); ok && s != "" {
			return s, nil
		}
	}
	return "", errors.New(`a command is {"text": "<device command>"}`)
}

// Duration is a profile duration: a string such as "90s" or "15m", or a
// number of seconds.
type Duration time.Duration

// D is the duration as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalJSON reads "90s" or 90.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case float64:
		*d = Duration(x * float64(time.Second))
	case string:
		p, err := time.ParseDuration(x)
		if err != nil {
			return fmt.Errorf("%q is not a duration such as 500ms, 10s or 1m", x)
		}
		*d = Duration(p)
	case nil:
		*d = 0
	default:
		return errors.New("a duration is a string such as \"10s\" or a number of seconds")
	}
	return nil
}

// MarshalJSON writes the duration as a string ("1m30s").
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }
