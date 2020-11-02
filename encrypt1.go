package cipherlib

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
)

func (e *Encrypt) Encrypt1(version, platform string, data []byte, param string) ([]byte, error) {
	sum, sumStr := md5Sum(param)

	key, ok := e.keys[version+"|"+platform]
	if !ok {
		return nil, ErrKeyMissed
	}

	realKey := getRealKey(e.Stoc, key, sumStr)
	iv, ivEncCrc := getRealIV(sum)
	ciphertext, err := aesEncrypt(data, realKey, iv)
	if err != nil {
		return nil, err
	}

	sign := signature(ciphertext, sumStr)

	annex := e.marshal(version, platform, param, "")

	out := make([]byte, len(sign)+1+len(annex)+1+len(ivEncCrc)+len(ciphertext))
	i := copy(out, sign)
	out[i] = '.'
	i++
	i += copy(out[i:], annex)
	out[i] = '.'
	i++
	i += copy(out[i:], ivEncCrc)
	copy(out[i:], ciphertext)
	return out, nil
}

func md5Sum(param string) ([]byte, string) {
	sum := md5.Sum([]byte(param))
	return sum[:], fmt.Sprintf("%02X", sum)
}

func getRealKey(stoc bool, key []byte, sumStr string) []byte {
	realKey := []byte(sumStr)
	if !stoc {
		for i := range realKey {
			realKey[i] ^= key[i]
		}
	} else {
		for i := range realKey {
			realKey[i] ^= ^key[i]
		}
	}
	return realKey
}

func getRealIV(sum []byte) (iv []byte, ivEncCrc []byte) {
	iv = make([]byte, 16)
	rand.Read(iv)
	ivEncCrc = make([]byte, 17)
	for i, v := range iv {
		ivEncCrc[i+1] = v ^ sum[i]
	}
	ivEncCrc[0] = crc8(ivEncCrc[1:])
	return iv, ivEncCrc
}
