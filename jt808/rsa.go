// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package jt808

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/cB-Sigma/trackers/track"
)

// RSA body encryption (body attribute bit 10, PropRSA), with the keys
// exchanged in 0x0A00 (terminal public key) and 0x8A00 (platform public
// key): a 4-byte public exponent e, then the modulus n (128 bytes for the
// 1024-bit keys the standard names; any length is read).
//
// The standard does not fix the block layout. We follow the form the
// published platform implementations use: PKCS #1 v1.5 encryption in
// blocks, the body cut into pieces of k-11 bytes (k the modulus length in
// bytes, 117 for a 1024-bit key), each piece encrypted to a block of k
// bytes, the blocks sent one after another. A received encrypted body is
// therefore a whole number of k-byte blocks, each decrypted on its own and
// the pieces joined. The body length field counts the encrypted bytes, so
// an encrypted body is at most 1023 bytes (7 blocks of a 1024-bit key,
// 819 bytes of plain body).

// Message IDs of the key exchange.
const (
	MTerminalRSA = 0x0A00
	MPlatformRSA = 0x8A00
)

// EncryptBody encrypts a body for the holder of pub, block by block.
func EncryptBody(pub *rsa.PublicKey, body []byte) ([]byte, error) {
	k := pub.Size()
	if k <= 11 {
		return nil, errors.New("jt808: RSA key too short")
	}
	var out []byte
	for len(body) > 0 {
		n := min(len(body), k-11)
		blk, err := rsa.EncryptPKCS1v15(rand.Reader, pub, body[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, blk...)
		body = body[n:]
	}
	return out, nil
}

// DecryptBody decrypts a body of whole k-byte blocks with priv.
func DecryptBody(priv *rsa.PrivateKey, body []byte) ([]byte, error) {
	k := priv.Size()
	if len(body)%k != 0 {
		return nil, fmt.Errorf("an RSA body is a whole number of %d-byte blocks, this one is %d bytes", k, len(body))
	}
	var out []byte
	for ; len(body) > 0; body = body[k:] {
		p, err := rsa.DecryptPKCS1v15(nil, priv, body[:k])
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

// PublicKeyBody is the body of a 0x0A00 or 0x8A00 message: e, then n.
func PublicKeyBody(pub *rsa.PublicKey) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(pub.E))
	return append(b, pub.N.FillBytes(make([]byte, pub.Size()))...)
}

// ParsePublicKeyBody reads a 0x0A00 or 0x8A00 body.
func ParsePublicKeyBody(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 4+64 {
		return nil, fmt.Errorf("an RSA public key body is 4 bytes of exponent and at least 64 of modulus, this one %d bytes", len(b))
	}
	e := binary.BigEndian.Uint32(b)
	if e < 3 || e%2 == 0 || e > 1<<31-1 {
		return nil, fmt.Errorf("RSA exponent %d is not an odd number from 3", e)
	}
	n := new(big.Int).SetBytes(b[4:])
	if n.BitLen() < 512 {
		return nil, errors.New("RSA modulus under 512 bits")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// parsePrivateKey reads a PEM RSA private key (PKCS #1 or PKCS #8).
func parsePrivateKey(s string) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, errors.New("rsaPrivateKey is not a PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("rsaPrivateKey is not a PKCS #1 or PKCS #8 RSA private key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("rsaPrivateKey is not an RSA key")
	}
	return rk, nil
}

// terminalRSA reads a 0x0A00: the terminal's public key is kept (commands
// to it are then encrypted) and answered with the platform's key (0x8A00),
// or with 0x8001 when the profile has none. It also answers an rsaKey
// command.
func (c *codec) terminalRSA(f *Frame, m *track.Message) {
	m.Kind = "response"
	m.Correlation = correlation(MPlatformRSA, 0)
	k, err := ParsePublicKeyBody(f.Body)
	if err != nil {
		m.Reply = c.general(f, ResultBadMessage)
		m.Warnings = append(m.Warnings, short(f, err))
		text := "the terminal's RSA public key could not be read"
		m.Response, m.Failed = &text, true
		return
	}
	c.keepTerminalKey(f.PhoneDigits(), k)
	text := fmt.Sprintf("terminal RSA public key, %d bits", k.N.BitLen())
	m.Response = &text
	m.Details = map[string]any{"rsaBits": k.N.BitLen()}
	if c.cfg.key == nil {
		m.Reply = c.general(f, ResultOK)
		return
	}
	m.Reply = c.reply(MPlatformRSA, PublicKeyBody(&c.cfg.key.PublicKey))
}

// terminalKey is the public key a terminal sent in 0x0A00.
func (c *codec) terminalKey(phone string) *rsa.PublicKey {
	sh := c.cfg.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.keys[trimPhone(phone)]
}

func (c *codec) keepTerminalKey(phone string, k *rsa.PublicKey) {
	sh := c.cfg.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if len(sh.keys) > 100000 {
		clear(sh.keys)
	}
	sh.keys[trimPhone(phone)] = k
}
