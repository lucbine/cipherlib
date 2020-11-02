package cipherlib

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"log"
)

func (d *Decrypt) Decrypt2(version, platform, param string, sign []byte, ciphertext []byte) (iv, ciphertext2 []byte, block cipher.Block, err error) {
	if len(ciphertext) < 35 {
		return nil, nil, nil, ErrCipherLenWrong
	}

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

	if string(sign) != signature(ciphertext[19:], string(sumBytes)) {
		return nil, nil, nil, ErrCheckSumWrong
	}

	block, err = d.getBlock2(version, platform, sumBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	iv, ciphertext, err = getIV2(ciphertext, sum)
	if err != nil {
		return nil, nil, nil, err
	}

	return iv, ciphertext, block, nil
}

func (d *Decrypt) getBlock2(version, platform string, sumBytes []byte) (cipher.Block, error) {
	if key, ok := d.blocks[version+"|"+platform]; ok {
		return aes.NewCipher(getRealKey2(d.Stoc, key, sumBytes))
	} else {
		log.Print(version, platform)
		return nil, ErrKeyMissed
	}
}

func getIV2(data []byte, sum []byte) (iv, ciphertext []byte, err error) {
	ivEnc := data[3:19]

	var g1, g2, lrc byte
	last, cur := byte(0), byte(0)
	for i := byte(0); i < 8; i++ {
		cur = ivEnc[i] >> 3
		g1 |= ((last ^ cur) & 0x01) << (7 - i)
		last = cur
	}
	if g1 != data[0] {
		return nil, nil, ErrCheckIVWrong
	}

	for i := byte(8); i < 16; i++ {
		cur = ivEnc[i] >> 3
		g2 |= ((last ^ cur) & 0x01) << (15 - i)
		last = cur
	}
	if g2 != data[2] {
		return nil, nil, ErrCheckIVWrong
	}

	for i := 0; i < 16; i++ {
		lrc += ivEnc[i]
	}
	lrc = ^lrc + 1
	if lrc != data[1] {
		return nil, nil, ErrCheckIVWrong
	}

	for i := 0; i < 16; i++ {
		ivEnc[i] = ^(ivEnc[i] ^ sum[i])
	}

	return ivEnc, data[19:], nil
}
