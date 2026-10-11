// Package jt808 is the JT/T 808 vehicle terminal protocol: frame reading
// and writing, decoding into track.Message, and command framing. JT/T 808
// is the Chinese road transport terminal standard used by many trackers
// and dashcams sold in India, Jimi IoT (Concox) JT808 models among them
// (VL and JC series); Traccar calls it "huabao", now "jt808". Our own
// implementation from the 2013 standard's published English translation
// (https://www.roadragon.com/uploads/JT808-protocol.pdf) and the 2019
// header change; Traccar's Jt808ProtocolDecoder and Jt808ProtocolEncoder
// were read for vendor behaviour only.
//
// Framing (frame.go): 0x7E, header, body, XOR check code, 0x7E, with 0x7E
// sent as 0x7D 0x02 and 0x7D as 0x7D 0x01. The header is the message ID,
// the body attributes (length, encryption, subpackage, and bit 14 for the
// 2019 form), the terminal phone number (BCD, 6 bytes; 10 bytes after a
// protocol version byte in the 2019 form) and the serial number. Replies
// use the device's header form. The phone number, as sent with its
// leading zeros, is the message's IMEI (the device's identity).
//
// Handled: 0x0100 registration (answered 0x8100 with an authentication
// code made for the terminal, or result 4 for a terminal that is not
// admitted), 0x0102 authentication, 0x0002 heartbeat and 0x0003 logout
// (answered 0x8001); 0x0200 location (location.go: alarm flags become
// alerts when they are first set, status bits and additional items 0x01
// mileage, 0x02 fuel, 0x03 tachograph speed, 0x25, 0x2A, 0x2B, 0x30
// signal and 0x31 satellites become status values, other items are kept
// as hexadecimal); 0x0704 batch (type 1, blind area, is history); 0x0201
// and 0x0500 (answers to a location query and to vehicle control, with a
// location); 0x0001 terminal general response; 0x6006 text and 0x0900
// pass-through answers as Jimi devices send them. Subpackaged messages
// are joined. Registrations in the JT/T 808-2011 layout (an 8-byte model
// field) are told from 2013 ones by their length; the record's
// protocolVersion says which. Active safety (safety.go): location items
// 0x64 ADAS, 0x65 DSM, 0x66 tyre pressure and 0x67 blind spot become
// alerts (code "0x64-0x04#11": item, alarm type, alarm ID) and status
// values with the alarm label; 0x1210, 0x1211 and 0x1212 attachment
// messages are read and answered (0x8001, 0x8001, 0x9212); attachment
// data packets are passed over. JT/T 1078 signalling (video.go): 0x1003
// attributes and 0x1205 resource lists are read as command answers. RSA
// (rsa.go): 0x0A00 keeps the terminal's key and is answered 0x8A00, and
// RSA bodies are decrypted with profile.rsaPrivateKey; other encryption,
// or RSA without the key, is answered "not supported". Any other message
// is acknowledged and passed over with a warning.
//
// Commands (command.go): {"text": "RELAY,1#"} is sent as 0x8300 text
// (Jimi devices take their SMS commands this way), or as 0x8900
// pass-through type 0xF0 for Jimi JC dashcams (textCommand). Named
// commands (track.Named): engineStop and engineResume as 0x8500 vehicle
// control with control flag 1 or 0 (engineControl; "text" sends RELAY,1#
// and RELAY,0#, "terminalControl" 0x8105 with 0xF0 or 0xF1), locate as
// 0x8201, reboot as 0x8105 command 4, interval as 0x8103 parameter 0x0029
// (Interval). Every command is answered, and the codec is a
// track.Correlator: a 0x0001 that names the command's serial and message
// ID (result 0 ok, 1 failure, 2 message error, 3 not supported), a 0x0201
// to a locate, a 0x0500 to vehicle control (failed when its fuel line
// status disagrees); an answer naming another command does not complete
// this one.
//
// Own-form commands ({"op": ...}, Ops): avAttributes (0x9003, answered
// 0x1003), live (0x9101: server, tcpPort, udpPort, channel, data av,
// video, talk, listen, broadcast or passThrough, stream main or sub),
// liveControl (0x9102: channel, control close, switchStream, pause,
// resume or closeTalk, close all, audio or video, stream), playback
// (0x9201: server, ports, channel, media av, audio, video or any, stream
// any, main or sub, storage any, main or backup, mode normal,
// fastForward, rewind, keyFrames or singleFrame, speed 1 to 16, start
// and end as RFC 3339 times), playbackControl (0x9202: channel, control
// start, pause, stop, fastForward, rewind, seek or keyFrames, speed, at),
// listResources (0x9205: channel, start, end, alarms, media, stream,
// storage; answered 0x1205), attachmentUpload (0x9208: server, ports,
// alarmLabel in hexadecimal as the location item gave it, alarmNumber)
// and rsaKey (0x8A00 with the platform key, answered 0x0A00). Commands to
// a terminal whose RSA key is known are encrypted (encryptCommands).
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true             # default true; false accepts frames whose XOR check code does not match
//	timezone: "+08:00"         # zone of the device's clock (default +08:00, the standard's); an IANA name or ±hh:mm
//	strictAuth: false          # default false; true admits a terminal's data only after it authenticates with the code issued to it (kept in memory)
//	engineControl: vehicleControl   # default vehicleControl (0x8500); text (RELAY,1# and RELAY,0#) or terminalControl (0x8105 0xF0/0xF1)
//	textCommand: "8300"        # default 8300 (text message); 8900 sends text as pass-through type 0xF0 (Jimi JC dashcams)
//	textFlag: 1                # default 1; the flag byte of a 0x8300 text message
//	awaitTextAnswer: false     # default false; true completes a text command with the device's text answer instead of its 0x0001
//	namedCommands: {reboot: "RESET#"}   # send a named command as this text instead (placeholders {seconds}, {imei})
//	failureWords: [error, fail, invalid]   # default; a text answer holding one fails the command
//	rsaPrivateKey: "-----BEGIN RSA PRIVATE KEY-----..."   # platform RSA key (PEM); reads RSA bodies, answers 0x0A00 with 0x8A00
//	encryptCommands: true      # default true; commands to a terminal whose RSA key is known are encrypted
package jt808

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cB-Sigma/trackers/track"
)

// Message IDs.
const (
	MTerminalResponse = 0x0001
	MHeartbeat        = 0x0002
	MLogout           = 0x0003
	MRegister         = 0x0100
	MAuth             = 0x0102
	MLocation         = 0x0200
	MLocateAnswer     = 0x0201
	MControlAnswer    = 0x0500
	MBatch            = 0x0704
	MUplinkPass       = 0x0900
	MTextReport       = 0x6006 // Jimi: the terminal's text answer
	MPlatformResponse = 0x8001
	MRegisterAnswer   = 0x8100
	MSetParams        = 0x8103
	MTerminalControl  = 0x8105
	MLocate           = 0x8201
	MText             = 0x8300
	MVehicleControl   = 0x8500
	MDownlinkPass     = 0x8900
)

// General response results.
const (
	ResultOK          = 0
	ResultFailure     = 1
	ResultBadMessage  = 2
	ResultUnsupported = 3
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CheckCRC (default true) drops frames whose XOR check code does not
	// match; false accepts them (firmware that computes it another way).
	CheckCRC *bool `json:"checkCrc,omitempty"`
	// Timezone is the zone of the device's clock: an IANA name or ±hh:mm
	// (default +08:00, which the standard prescribes).
	Timezone string `json:"timezone,omitempty"`
	// StrictAuth (default false) takes a terminal's data only after it
	// authenticated (0x0102) with the code this NewCodec call issued at its
	// registration. Codes are kept in memory: after a restart a terminal
	// must register again, which standard terminals do when their
	// authentication is refused.
	StrictAuth bool `json:"strictAuth,omitempty"`
	// EngineControl is how engineStop and engineResume are sent:
	// vehicleControl (default, 0x8500 control flag 1 or 0), text (the
	// namedCommands text, default RELAY,1# and RELAY,0#, as Jimi devices
	// take it) or terminalControl (0x8105 command 0xF0 or 0xF1, a vendor
	// form).
	EngineControl string `json:"engineControl,omitempty"`
	// TextCommand is the message that carries text commands: 8300
	// (default, text message) or 8900 (pass-through type 0xF0, Jimi JC
	// dashcams).
	TextCommand string `json:"textCommand,omitempty"`
	// TextFlag is the flag byte of a 0x8300 text message (default 1).
	TextFlag *int `json:"textFlag,omitempty"`
	// AwaitTextAnswer (default false) completes a text command with the
	// device's text answer (0x6006 or 0x0900) instead of its general
	// response, which only says the text was received.
	AwaitTextAnswer bool `json:"awaitTextAnswer,omitempty"`
	// NamedCommands replaces a named command by a text command for
	// firmware that takes it so ({seconds}, {imei}); "" turns it off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// FailureWords are the words (any case) whose presence in a text
	// answer fails the command (default error, fail, invalid).
	FailureWords []string `json:"failureWords,omitempty"`
	// RSAPrivateKey is the platform's RSA private key (PEM, PKCS #1 or
	// PKCS #8). With it, RSA-encrypted bodies are decrypted, a terminal's
	// 0x0A00 is answered with the platform public key (0x8A00) and the
	// rsaKey command sends it. Without it encrypted bodies are answered
	// "not supported".
	RSAPrivateKey string `json:"rsaPrivateKey,omitempty"`
	// EncryptCommands (default true) encrypts commands to a terminal whose
	// public key (0x0A00) is known.
	EncryptCommands *bool `json:"encryptCommands,omitempty"`
}

// Interval bounds the interval command (0x8103 parameter 0x0029, seconds).
var Interval = track.IntervalRange{Min: 1, Max: 86400}

// NamedActions are the named commands JT808 has: all of them.
var NamedActions = track.Actions

type config struct {
	crc        bool
	loc        *time.Location
	strictAuth bool
	engine     string
	text8900   bool
	textFlag   byte
	awaitText  bool
	named      track.NamedTemplates
	fail       []string
	key        *rsa.PrivateKey
	encrypt    bool
	sh         *shared
}

// shared is the state of every codec one NewCodec call makes.
type shared struct {
	mu     sync.Mutex
	codes  map[string]string         // phone (no leading zeros) → issued authentication code
	engine map[string]bool           // phone#serial of a 0x8500 command → fuel line cut expected
	keys   map[string]*rsa.PublicKey // phone (no leading zeros) → terminal RSA public key
}

// NewCodec reads a Profile (empty for the defaults) and returns the maker
// of one codec per connection. The connections of one maker share the
// authentication codes issued at registration and the expected outcome of
// vehicle control commands.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := &config{crc: p.CheckCRC == nil || *p.CheckCRC, strictAuth: p.StrictAuth, awaitText: p.AwaitTextAnswer, textFlag: 1,
		named: p.NamedCommands, encrypt: p.EncryptCommands == nil || *p.EncryptCommands,
		sh: &shared{codes: map[string]string{}, engine: map[string]bool{}, keys: map[string]*rsa.PublicKey{}}}
	if p.RSAPrivateKey != "" {
		k, err := parsePrivateKey(p.RSAPrivateKey)
		if err != nil {
			return nil, err
		}
		c.key = k
	}
	loc, err := zone(p.Timezone)
	if err != nil {
		return nil, err
	}
	c.loc = loc
	switch p.EngineControl {
	case "", "vehicleControl":
		c.engine = "vehicleControl"
	case "text", "terminalControl":
		c.engine = p.EngineControl
	default:
		return nil, fmt.Errorf("engineControl %q is not vehicleControl, text or terminalControl", p.EngineControl)
	}
	switch p.TextCommand {
	case "", "8300":
	case "8900":
		c.text8900 = true
	default:
		return nil, fmt.Errorf("textCommand %q is not 8300 or 8900", p.TextCommand)
	}
	if p.TextFlag != nil {
		if *p.TextFlag < 0 || *p.TextFlag > 255 {
			return nil, fmt.Errorf("textFlag %d is not 0 to 255", *p.TextFlag)
		}
		c.textFlag = byte(*p.TextFlag)
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	if c.fail, err = track.FailureWords(p.FailureWords, "error", "fail", "invalid"); err != nil {
		return nil, err
	}
	return func() track.Codec { return &codec{cfg: c, parts: map[uint16]*parts{}} }, nil
}

// zone reads a timezone setting: "" is +08:00.
func zone(s string) (*time.Location, error) {
	if s == "" {
		s = "+08:00"
	}
	if len(s) == 6 && (s[0] == '+' || s[0] == '-') && s[3] == ':' {
		t, err := time.Parse("-07:00", s)
		if err == nil {
			_, off := t.Zone()
			return time.FixedZone("UTC"+s, off), nil
		}
	}
	l, err := time.LoadLocation(s)
	if err != nil {
		return nil, fmt.Errorf("timezone %q is not an IANA zone name or ±hh:mm", s)
	}
	return l, nil
}

// codec is one connection's state.
type codec struct {
	cfg *config

	mu      sync.Mutex // the header form and serial, shared with Command
	version int        // -1: 2013 header
	phone   []byte
	known   bool
	serial  uint16

	afterFrame bool
	authed     bool
	prevAlarm  uint32
	prevHist   uint32
	prevACC    *bool
	parts      map[uint16]*parts
	lists      map[uint16]uint16 // serial of a 0x9201 or 0x9205 → its ID
	lastFile   string
}

// parts collects the pieces of a subpackaged message.
type parts struct {
	total  uint16
	got    map[uint16][]byte
	header Header
	size   int
}

func trimPhone(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return s
	}
	return t
}

// reply builds a platform message in the device's header form.
func (c *codec) reply(id uint16, body []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serial++
	return Encode(Header{ID: id, Version: c.version, Phone: c.phone, Serial: c.serial}, body)
}

// general is a 0x8001 platform general response to frame f.
func (c *codec) general(f *Frame, result byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, f.Serial)
	b = binary.BigEndian.AppendUint16(b, f.ID)
	return c.reply(MPlatformResponse, append(b, result))
}

func skip(code, msg, detail string) error {
	return &track.Skip{Warning: track.Warning{Code: code, Msg: msg, Detail: detail}}
}

// maxBody bounds a joined subpackaged message.
const maxBody = 256 << 10

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	if ok, err := c.skipFileData(r); ok {
		return nil, err
	}
	raw, err := readRaw(r, c.afterFrame)
	c.afterFrame = false
	if errors.Is(err, errTooLong) {
		return nil, skip("unknownPacket", "A packet longer than the protocol allows was passed over (the connection stays up).", "")
	}
	if err != nil {
		return nil, err
	}
	c.afterFrame = true
	f, err := ParseFrame(Unescape(raw))
	if err != nil {
		return nil, skip("shortPacket", "A packet shorter than its header was passed over (the connection stays up).", fmt.Sprintf("% X", raw))
	}
	if !f.CheckOK && c.cfg.crc {
		return nil, &track.Skip{Warning: track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc", Detail: fmt.Sprintf("0x%04X", f.ID),
			Msg: "A packet whose check code does not match was dropped. Set profile.checkCrc to false if the device computes it another way."}}
	}
	c.mu.Lock()
	c.version, c.phone, c.known = f.Version, f.Phone, true
	c.mu.Unlock()
	m := &track.Message{IMEI: f.PhoneDigits()}
	if f.Props&propEncrypt != 0 {
		if f.Props&propEncrypt != PropRSA || c.cfg.key == nil {
			m.Reply = c.general(f, ResultUnsupported)
			m.Warnings = append(m.Warnings, track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("0x%04X encrypted", f.ID), Setting: "profile.rsaPrivateKey",
				Msg: "An encrypted message was answered as not supported and passed over. RSA bodies are read with profile.rsaPrivateKey set; other encryption is not read: turn it off on the device."})
			return m, nil
		}
		body, err := DecryptBody(c.cfg.key, f.Body)
		if err != nil {
			m.Reply = c.general(f, ResultBadMessage)
			m.Warnings = append(m.Warnings, track.Warning{Code: "decryptFailed", Detail: fmt.Sprintf("0x%04X: %v", f.ID, err), Setting: "profile.rsaPrivateKey",
				Msg: "An RSA-encrypted message could not be decrypted with the platform key and was answered as a message error. Check that the terminal holds the platform public key of profile.rsaPrivateKey."})
			return m, nil
		}
		f.Body = body
	}
	if f.Props&propSubpacket != 0 && f.Total > 1 {
		body, done := c.join(f)
		if !done {
			m.Reply = c.general(f, ResultOK)
			return m, nil
		}
		f.Body = body
	}
	return c.message(f, m)
}

// join keeps a piece of a subpackaged message; when the last piece is in
// it returns the whole body.
func (c *codec) join(f *Frame) ([]byte, bool) {
	p := c.parts[f.ID]
	if p == nil || p.total != f.Total || f.Index == 1 {
		p = &parts{total: f.Total, got: map[uint16][]byte{}, header: f.Header}
		c.parts[f.ID] = p
	}
	if _, dup := p.got[f.Index]; !dup && f.Index >= 1 && f.Index <= f.Total {
		p.got[f.Index] = append([]byte(nil), f.Body...)
		p.size += len(f.Body)
	}
	if p.size > maxBody {
		delete(c.parts, f.ID)
		return nil, false
	}
	if len(p.got) < int(p.total) {
		return nil, false
	}
	var body []byte
	for i := uint16(1); i <= p.total; i++ {
		body = append(body, p.got[i]...)
	}
	delete(c.parts, f.ID)
	return body, true
}

func gbkText(b []byte) string {
	s := strings.TrimRight(string(b), "\x00 ")
	return strings.ToValidUTF8(s, "?")
}

func (c *codec) message(f *Frame, m *track.Message) (*track.Message, error) {
	b := f.Body
	gated := c.cfg.strictAuth && !c.authed
	switch f.ID {
	case MRegister, MAuth, MHeartbeat, MLogout, MTerminalResponse,
		// The attachment server's connection does not authenticate.
		MAlarmAttachments, MFileInfo, MFileDone:
	default:
		if gated {
			m.Reply = c.general(f, ResultFailure)
			m.Warnings = append(m.Warnings, track.Warning{Code: "authFailed", Setting: "profile.strictAuth", Detail: fmt.Sprintf("0x%04X", f.ID),
				Msg: "A terminal sent data before authenticating with the code issued to it; the data was refused. The terminal registers again on its own; strictAuth false takes data without it."})
			return m, nil
		}
	}
	switch f.ID {
	case MRegister:
		m.Login, m.Kind = true, "login"
		st := registration(b, f.V2019())
		if len(st) == 0 {
			m.Warnings = append(m.Warnings, short(f, fmt.Errorf("a registration of %d bytes fits no layout", len(b))))
		}
		code := c.issue(f.PhoneDigits())
		body := binary.BigEndian.AppendUint16(nil, f.Serial)
		m.Reply = c.reply(MRegisterAnswer, append(append(body, 0), code...))
		m.Reject = c.reply(MRegisterAnswer, append(binary.BigEndian.AppendUint16(nil, f.Serial), 4))
		m.Records = []track.Record{{Status: st}}
	case MAuth:
		m.Login, m.Kind = true, "login"
		code, st := authentication(b, f.V2019())
		m.Reject = c.general(f, ResultFailure)
		if c.cfg.strictAuth && !c.checkCode(f.PhoneDigits(), code) {
			c.authed = false
			m.Reply = m.Reject
			m.Warnings = append(m.Warnings, track.Warning{Code: "authFailed", Setting: "profile.strictAuth", Detail: code,
				Msg: "A terminal authenticated with a code this codec did not issue to it and was refused; it registers again on its own. strictAuth false takes any code."})
			return m, nil
		}
		c.authed = true
		m.Reply = c.general(f, ResultOK)
		if len(st) > 0 {
			m.Records = []track.Record{{Status: st}}
		}
	case MHeartbeat:
		m.Kind = "heartbeat"
		m.Reply = c.general(f, ResultOK)
	case MLogout:
		m.Kind = "logout"
		c.authed = false
		m.Reply = c.general(f, ResultOK)
	case MLocation:
		m.Kind = "normal"
		m.Reply = c.general(f, ResultOK)
		rec, err := c.record(b, false)
		if err != nil {
			m.Warnings = append(m.Warnings, short(f, err))
			return m, nil
		}
		m.Records = []track.Record{*rec}
	case MBatch:
		m.Kind = "normal"
		m.Reply = c.general(f, ResultOK)
		if len(b) < 3 {
			m.Warnings = append(m.Warnings, short(f, errors.New("no item count")))
			return m, nil
		}
		n, hist := int(binary.BigEndian.Uint16(b)), b[2] == 1
		rest := b[3:]
		for i := 0; i < n && len(rest) >= 2; i++ {
			l := int(binary.BigEndian.Uint16(rest))
			if len(rest) < 2+l {
				m.Warnings = append(m.Warnings, short(f, fmt.Errorf("item %d is cut short", i+1)))
				break
			}
			rec, err := c.record(rest[2:2+l], hist)
			if err != nil {
				m.Warnings = append(m.Warnings, short(f, err))
			} else {
				m.Records = append(m.Records, *rec)
			}
			rest = rest[2+l:]
		}
	case MLocateAnswer, MControlAnswer:
		m.Kind = "response"
		if len(b) < 2 {
			m.Warnings = append(m.Warnings, short(f, errors.New("no serial")))
			return m, nil
		}
		serial := binary.BigEndian.Uint16(b)
		cmd := uint16(MLocate)
		if f.ID == MControlAnswer {
			cmd = MVehicleControl
		}
		m.Correlation = correlation(cmd, serial)
		rec, err := c.record(b[2:], false)
		if err != nil {
			text := "answered without a position"
			m.Response = &text
			m.Warnings = append(m.Warnings, short(f, err))
			return m, nil
		}
		m.Records = []track.Record{*rec}
		fx := rec.Fix
		m.Details = map[string]any{"lat": fx.Lat, "lon": fx.Lon, "fix": fx.Valid}
		text := fmt.Sprintf("position %.6f,%.6f", fx.Lat, fx.Lon)
		if f.ID == MControlAnswer {
			cut := rec.Status["fuelCut"] == true || rec.Status["circuitCut"] == true
			m.Details["fuelCut"] = cut
			text = "fuel line restored"
			if cut {
				text = "fuel line cut"
			}
			if want, ok := c.expected(f.PhoneDigits(), serial); ok && want != cut {
				m.Failed = true
				text = "the vehicle reports " + text + ", not what the command asked"
			}
		}
		m.Response = &text
	case MTerminalResponse:
		m.Kind = "response"
		if len(b) < 5 {
			m.Warnings = append(m.Warnings, short(f, errors.New("general response under 5 bytes")))
			return m, nil
		}
		serial, id, res := binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), b[4]
		if c.cfg.awaitText && res == ResultOK && (id == MText || id == MDownlinkPass) {
			// Received only; the text answer completes the command.
			return m, nil
		}
		text := resultText(res)
		m.Response, m.Failed = &text, res != ResultOK
		m.Correlation = correlation(id, serial)
		m.Details = map[string]any{"result": int(res), "answerTo": fmt.Sprintf("0x%04X", id)}
		if id == MAVAttributesQuery || id == MPlatformRSA {
			// Their own answers (0x1003, 0x0A00) name no serial.
			m.Correlation = correlation(id, 0)
		}
	case MTerminalRSA:
		c.terminalRSA(f, m)
	case MAVAttributes, MResourceList:
		c.videoMessage(f, m)
	case MAlarmAttachments, MFileInfo, MFileDone:
		c.attachmentMessage(f, m)
	case MTextReport:
		m.Kind = "response"
		m.Reply = c.general(f, ResultOK)
		if len(b) < 1 {
			return m, nil
		}
		text := gbkText(b[1:])
		m.Response, m.Failed = &text, track.AnswerFailed(text, c.cfg.fail)
	case MUplinkPass:
		m.Reply = c.general(f, ResultOK)
		if len(b) < 1 {
			return m, nil
		}
		if text := gbkText(b[1:]); printable(text) {
			m.Kind = "response"
			m.Response, m.Failed = &text, track.AnswerFailed(text, c.cfg.fail)
		} else {
			m.Records = []track.Record{{Status: map[string]any{fmt.Sprintf("passThrough0x%02X", b[0]): fmt.Sprintf("%X", b[1:])}}}
		}
	default:
		// Acknowledged so the device does not send it again, and passed
		// over.
		m.Reply = c.general(f, ResultOK)
		m.Warnings = append(m.Warnings, track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("0x%04X", f.ID),
			Msg: "A message this codec does not read was acknowledged and passed over."})
	}
	return m, nil
}

func short(f *Frame, err error) track.Warning {
	return track.Warning{Code: "shortPacket", Detail: fmt.Sprintf("0x%04X: %v", f.ID, err),
		Msg: "A message shorter than the protocol needs was acknowledged and passed over (the connection stays up)."}
}

func printable(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\r' && r != '\n' && r != '\t' {
			return false
		}
	}
	return !strings.ContainsRune(s, utf8.RuneError)
}

func resultText(r byte) string {
	switch r {
	case ResultOK:
		return "ok"
	case ResultFailure:
		return "failed (result 1)"
	case ResultBadMessage:
		return "message error (result 2)"
	case ResultUnsupported:
		return "not supported (result 3)"
	}
	return fmt.Sprintf("failed (result %d)", r)
}

// correlation names a command by its message ID and serial.
func correlation(id, serial uint16) string { return fmt.Sprintf("%04X#%d", id, serial) }

// record turns a location body into a record, with alerts for alarm
// flags newly set (and ignition changes, live only).
func (c *codec) record(b []byte, history bool) (*track.Record, error) {
	l, err := ParseLocation(b, c.cfg.loc)
	if err != nil {
		return nil, err
	}
	fx := l.Fix
	rec := &track.Record{Fix: &fx, Status: l.StatusValues(), History: history, Time: fx.Time}
	if history {
		rec.Alerts = append(l.alertsFor(c.prevHist), l.SafetyAlerts()...)
		c.prevHist = l.Alarm
		return rec, nil
	}
	rec.Alerts = append(l.alertsFor(c.prevAlarm), l.SafetyAlerts()...)
	c.prevAlarm = l.Alarm
	acc := l.Status&StACC != 0
	if c.prevACC != nil && *c.prevACC != acc {
		typ := "ignition-off"
		if acc {
			typ = "ignition-on"
		}
		rec.Alerts = append(rec.Alerts, track.NewAlert(typ, "status-bit0"))
	}
	c.prevACC = &acc
	return rec, nil
}

// registration reads a 0x0100 body (2019, 2013 or the shorter 2011
// layout) into status values.
func registration(b []byte, v2019 bool) map[string]any {
	st := map[string]any{}
	var maker, model, id int
	switch registrationLayout(b, v2019) {
	case "2019":
		maker, model, id = 11, 30, 30
	case "2013":
		maker, model, id = 5, 20, 7
	case "2011":
		maker, model, id = 5, 8, 7
	default:
		return st
	}
	st["protocolVersion"] = registrationLayout(b, v2019)
	p := 4
	st["manufacturer"] = gbkText(b[p : p+maker])
	p += maker
	st["model"] = gbkText(b[p : p+model])
	p += model
	st["terminalId"] = gbkText(b[p : p+id])
	p += id
	st["plateColor"] = int(b[p])
	if p+1 < len(b) {
		st["plate"] = gbkText(b[p+1:])
	}
	return st
}

// plateColors are the plate colour codes (JT/T 415: 1 blue, 2 yellow, 3
// black, 4 white, 9 other; 0 for a vehicle without a plate, and 5 green
// as used for new-energy plates).
func plateColor(b byte) bool { return b <= 5 || b == 9 }

// registrationLayout tells the 0x0100 layouts apart by length: 2019 (the
// 2019 header), 2013 (manufacturer 5, model 20, terminal ID 7: 37 bytes
// before the plate) or 2011 (model 8: 25 bytes before the plate). A body
// of 37 bytes or more is 2013 unless its plate colour byte is not one
// while the 2011 reading has one (a 2011 body with a long plate).
func registrationLayout(b []byte, v2019 bool) string {
	switch {
	case v2019 && len(b) >= 76:
		return "2019"
	case v2019:
		return ""
	case len(b) >= 37 && (plateColor(b[36]) || !plateColor(b[24])):
		return "2013"
	case len(b) >= 25:
		return "2011"
	}
	return ""
}

// authentication reads a 0x0102 body: the code, and in the 2019 form the
// IMEI and software version.
func authentication(b []byte, v2019 bool) (string, map[string]any) {
	if v2019 && len(b) >= 1 && len(b) >= 1+int(b[0]) {
		n := int(b[0])
		code := string(b[1 : 1+n])
		rest := b[1+n:]
		st := map[string]any{}
		if len(rest) >= 15 {
			st["imei"] = gbkText(rest[:15])
			if len(rest) >= 35 {
				st["firmware"] = gbkText(rest[15:35])
			}
		}
		return code, st
	}
	return string(b), nil
}

// issue returns the authentication code of a terminal, made at its first
// registration.
func (c *codec) issue(phone string) string {
	sh := c.cfg.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	k := trimPhone(phone)
	if code, ok := sh.codes[k]; ok {
		return code
	}
	var r [6]byte
	_, _ = rand.Read(r[:])
	code := strings.ToUpper(hex.EncodeToString(r[:]))
	sh.codes[k] = code
	return code
}

func (c *codec) checkCode(phone, code string) bool {
	sh := c.cfg.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	want, ok := sh.codes[trimPhone(phone)]
	return ok && want == code
}
