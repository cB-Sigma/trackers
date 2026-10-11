package jt808

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Flag is the byte that opens and closes every frame.
const Flag = 0x7E

// Property bits of the header's message body attribute word.
const (
	propLength    = 0x03FF // body length
	propEncrypt   = 0x1C00 // encryption (bit 10 RSA)
	propSubpacket = 0x2000 // the body is one piece of a longer message
	propVersion   = 0x4000 // 2019 header: protocol version byte, 10-byte phone number
)

// Header is a frame header.
type Header struct {
	ID    uint16
	Props uint16
	// Version is the protocol version byte of a 2019 header (Props bit
	// 14); -1 for a 2013 header.
	Version int
	// Phone is the terminal phone number as sent: BCD, 6 bytes (2013) or
	// 10 bytes (2019).
	Phone  []byte
	Serial uint16
	// Total and Index number the pieces of a subpackaged message (Props
	// bit 13); 0 otherwise.
	Total, Index uint16
}

// V2019 reports whether the header is the 2019 form.
func (h Header) V2019() bool { return h.Version >= 0 }

// PhoneDigits is the terminal phone number as the device sent it, leading
// zeros kept (non-BCD nibbles are written as hexadecimal digits).
func (h Header) PhoneDigits() string { return fmt.Sprintf("%X", h.Phone) }

// Frame is one decoded frame: header and body (unescaped, check code
// verified when asked).
type Frame struct {
	Header
	Body []byte
	// CheckOK reports whether the XOR check code matched.
	CheckOK bool
}

// errTooLong is a frame longer than any the protocol allows; the reader
// passed over it.
var errTooLong = errors.New("jt808: frame too long")

// readRaw reads the escaped content of the next frame (between flags).
// afterFrame says the previous frame ended just before, so content that
// does not start with a flag is a frame sharing that closing flag.
func readRaw(r *bufio.Reader, afterFrame bool) ([]byte, error) {
	if !afterFrame {
		for {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == Flag {
				break
			}
		}
	}
	for {
		s, err := r.ReadSlice(Flag)
		if errors.Is(err, bufio.ErrBufferFull) {
			// Pass over the rest of this frame.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice(Flag)
			}
			if err != nil {
				return nil, err
			}
			return nil, errTooLong
		}
		if err != nil {
			return nil, err
		}
		if len(s) == 1 {
			// Two flags in a row: the second opens the frame.
			continue
		}
		return append([]byte(nil), s[:len(s)-1]...), nil
	}
}

// Unescape restores 0x7D 0x02 to 0x7E and 0x7D 0x01 to 0x7D; a 0x7D
// followed by anything else is kept as sent.
func Unescape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x7D && i+1 < len(b) {
			switch b[i+1] {
			case 0x01:
				out = append(out, 0x7D)
				i++
				continue
			case 0x02:
				out = append(out, 0x7E)
				i++
				continue
			}
		}
		out = append(out, b[i])
	}
	return out
}

// Escape replaces 0x7E by 0x7D 0x02 and 0x7D by 0x7D 0x01.
func Escape(b []byte) []byte {
	out := make([]byte, 0, len(b)+4)
	for _, v := range b {
		switch v {
		case 0x7E:
			out = append(out, 0x7D, 0x02)
		case 0x7D:
			out = append(out, 0x7D, 0x01)
		default:
			out = append(out, v)
		}
	}
	return out
}

// Check is the XOR of every byte.
func Check(b []byte) byte {
	var c byte
	for _, v := range b {
		c ^= v
	}
	return c
}

// errShort is a frame shorter than its header.
var errShort = errors.New("jt808: frame shorter than its header")

// ParseFrame reads an unescaped frame (header, body and check code).
func ParseFrame(b []byte) (*Frame, error) {
	if len(b) < 13 {
		return nil, errShort
	}
	f := &Frame{CheckOK: Check(b[:len(b)-1]) == b[len(b)-1]}
	b = b[:len(b)-1]
	f.ID = binary.BigEndian.Uint16(b[0:2])
	f.Props = binary.BigEndian.Uint16(b[2:4])
	f.Version = -1
	p := 4
	phoneLen := 6
	if f.Props&propVersion != 0 {
		f.Version = int(b[4])
		p = 5
		phoneLen = 10
	}
	if len(b) < p+phoneLen+2 {
		return nil, errShort
	}
	f.Phone = append([]byte(nil), b[p:p+phoneLen]...)
	p += phoneLen
	f.Serial = binary.BigEndian.Uint16(b[p:])
	p += 2
	if f.Props&propSubpacket != 0 {
		if len(b) < p+4 {
			return nil, errShort
		}
		f.Total = binary.BigEndian.Uint16(b[p:])
		f.Index = binary.BigEndian.Uint16(b[p+2:])
		p += 4
	}
	f.Body = b[p:]
	return f, nil
}

// ReadFrame reads the next frame from r, skipping bytes before a flag. A
// frame whose check code does not match is returned with CheckOK false.
func ReadFrame(r *bufio.Reader) (*Frame, error) {
	raw, err := readRaw(r, false)
	if err != nil {
		return nil, err
	}
	return ParseFrame(Unescape(raw))
}

// Encode builds an escaped frame with flags. The header's Version,
// Phone, ID and Serial are used; length and version bits are set from
// the body and Version (never subpackaged).
func Encode(h Header, body []byte) []byte {
	h.Props, h.Total, h.Index = 0, 0, 0
	return EncodeWith(h, body)
}

// PropRSA is the body attribute bit of an RSA-encrypted body (bit 10).
const PropRSA = 0x0400

// EncodeWith is Encode that also keeps the encryption bits of h.Props
// (PropRSA) and, when h.Total is above 0, frames the body as piece
// h.Index of h.Total of a subpackaged message.
func EncodeWith(h Header, body []byte) []byte {
	props := uint16(len(body))&propLength | h.Props&propEncrypt
	if h.Total > 0 {
		props |= propSubpacket
	}
	b := binary.BigEndian.AppendUint16(nil, h.ID)
	if h.V2019() {
		props |= propVersion
		b = binary.BigEndian.AppendUint16(b, props)
		b = append(b, byte(h.Version))
	} else {
		b = binary.BigEndian.AppendUint16(b, props)
	}
	b = append(b, h.Phone...)
	b = binary.BigEndian.AppendUint16(b, h.Serial)
	if h.Total > 0 {
		b = binary.BigEndian.AppendUint16(b, h.Total)
		b = binary.BigEndian.AppendUint16(b, h.Index)
	}
	b = append(b, body...)
	b = append(b, Check(b))
	out := append([]byte{Flag}, Escape(b)...)
	return append(out, Flag)
}

// PhoneBCD encodes phone number digits as BCD of n bytes, padded with
// leading zeros (the rightmost digits are kept when there are too many).
func PhoneBCD(digits string, n int) []byte {
	digits = strings.TrimSpace(digits)
	if len(digits) > 2*n {
		digits = digits[len(digits)-2*n:]
	}
	digits = strings.Repeat("0", 2*n-len(digits)) + digits
	out := make([]byte, n)
	for i := range n {
		out[i] = nib(digits[2*i])<<4 | nib(digits[2*i+1])
	}
	return out
}

func nib(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 0
}

// bcdFields reads a BCD[6] YYMMDDhhmmss time; ok is false when a field is
// not decimal or out of range.
func bcdFields(b []byte) ([6]int, bool) {
	var v [6]int
	if len(b) < 6 {
		return v, false
	}
	for i := range 6 {
		hi, lo := b[i]>>4, b[i]&0x0F
		if hi > 9 || lo > 9 {
			return v, false
		}
		v[i] = int(hi)*10 + int(lo)
	}
	return v, true
}

// BCD encodes a number of two decimal digits.
func BCD(v int) byte { return byte(v/10)<<4 | byte(v%10) }

// BCDTime encodes t as BCD[6] YYMMDDhhmmss in zone loc; the zero time is
// six zero bytes.
func BCDTime(t time.Time, loc *time.Location) []byte {
	if t.IsZero() {
		return make([]byte, 6)
	}
	t = t.In(loc)
	return []byte{BCD(t.Year() % 100), BCD(int(t.Month())), BCD(t.Day()), BCD(t.Hour()), BCD(t.Minute()), BCD(t.Second())}
}

// bcdTime reads a BCD[6] time in zone loc as UTC; ok is false for an
// invalid or all-zero time.
func bcdTime(b []byte, loc *time.Location) (time.Time, bool) {
	v, ok := bcdFields(b)
	if !ok || v[1] < 1 || v[1] > 12 || v[2] < 1 || v[2] > 31 || v[3] > 23 || v[4] > 59 || v[5] > 59 {
		return time.Time{}, false
	}
	return time.Date(2000+v[0], time.Month(v[1]), v[2], v[3], v[4], v[5], 0, loc).UTC(), true
}
