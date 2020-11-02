package cipherlib

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"strings"
)

func (e *Encrypt) Encrypt2(version, platform string, data []byte, param string) ([]byte, error) {
	sum := md5Sum2(param)
	sumBytes := make([]byte, 32)
	if !isValidUUID(param) {
		hex.Encode(sumBytes, sum)
	} else {
		uuid, _ := parseUUID(param)
		for i := 0; i < 16; i++ {
			sumBytes[2*i] = sum[i]
			sumBytes[2*i+1] = uuid[15-i]
		}
	}

	key, ok := e.keys[version+"|"+platform]
	if !ok {
		return nil, ErrKeyMissed
	}

	realKey := getRealKey2(e.Stoc, key, sumBytes)

	iv, ivEnc, g1, g2, lrc := genIVAndEnc(sum)

	ciphertext, err := aesEncrypt(data, realKey, iv)
	if err != nil {
		return nil, err
	}

	sign := signature(ciphertext, string(sumBytes))

	annex := e.marshal(version, platform, param, "1")

	out := make([]byte, len(sign)+1+len(annex)+1+19+len(ciphertext))
	i := copy(out, sign)
	out[i] = '.'
	i++
	i += copy(out[i:], annex)
	out[i] = '.'
	i++
	out[i] = g1
	i++
	out[i] = lrc
	i++
	out[i] = g2
	i++
	i += copy(out[i:], ivEnc)
	copy(out[i:], ciphertext)
	return out, nil
}

func md5Sum2(param string) []byte {
	sum := md5.Sum([]byte(param))
	return sum[:]
}

func getRealKey2(stoc bool, key []byte, sumBytes []byte) (enc []byte) {
	enc = make([]byte, 32)
	for i, v := range sumBytes {
		if parityTable256[v] == 1 {
			enc[i] = (^key[i]) ^ grayCodes[v]
		} else {
			enc[i] = reverses[key[i]] ^ v
		}
	}
	return enc
}

func genIVAndEnc(sum []byte) (iv []byte, ivEnc []byte, g1, g2, lrc byte) {
	iv = make([]byte, 16)
	rand.Read(iv)

	ivEnc = make([]byte, 16)
	for i := 0; i < 16; i++ {
		ivEnc[i] = (^iv[i]) ^ sum[i]
	}

	last, cur := byte(0), byte(0)
	for i := byte(0); i < 8; i++ {
		cur = ivEnc[i] >> 3
		g1 |= ((last ^ cur) & 0x01) << (7 - i)
		last = cur
	}
	for i := byte(8); i < 16; i++ {
		cur = ivEnc[i] >> 3
		g2 |= ((last ^ cur) & 0x01) << (15 - i)
		last = cur
	}

	for i := 0; i < 16; i++ {
		lrc += ivEnc[i]
	}
	lrc = ^lrc + 1
	return iv, ivEnc, g1, g2, lrc
}

func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}

	var nchar, nhyphen int
	for _, v := range []byte(uuid) {
		switch {
		case v >= '0' && v <= '9':
			nchar++
		case v >= 'a' && v <= 'f':
			nchar++
		case v >= 'A' && v <= 'F':
			nchar++
		case v == '-':
			nhyphen++
		default:
			return false
		}
	}
	return nchar == 32 && nhyphen == 4
}

func parseUUID(uuid string) ([]byte, error) {
	return hex.DecodeString(strings.Replace(uuid, "-", "", -1))
}

var parityTable256 = []byte{
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
}

var grayCodes [256]byte
var reverses [256]byte

func init() {
	for i := 0; i <= 255; i++ {
		b := byte(i)
		grayCodes[i] = b & 0x80
		for j := byte(1); j <= 7; j++ {
			grayCodes[i] |= ((b >> 1) ^ b) & (1 << (7 - j))
		}
	}
	for i := 0; i <= 255; i++ {
		b := byte(i)
		for j := byte(0); j <= 7; j++ {
			reverses[i] |= ((b >> (7 - j)) & 0x01) << j
		}
	}
}
