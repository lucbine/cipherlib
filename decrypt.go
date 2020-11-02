package cipherlib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"log"
	"strings"
)

var (
	ErrDotPartsWrong   = errors.New("dot parts not correct")
	ErrGroupsNotEnough = errors.New("groups not enough")
	ErrUnitsNotEnough  = errors.New("units not enough")
	ErrKeyMissed       = errors.New("key missed for this version and platform")
	ErrIVCheckError    = errors.New("IV check error")
	ErrCipherLenWrong  = errors.New("cipher text lenght error")
	ErrKeyLenWrong     = errors.New("key lenght must be 32 bytes")
	ErrPaddingWrong    = errors.New("padding not correct")
	ErrCheckSumWrong   = errors.New("check sum wrong")
	ErrUnsupportedUnit = errors.New("unsupported unit")
	ErrEncWrong        = errors.New("enc wrong")
	ErrCheckIVWrong    = errors.New("check iv wrong")
)

type Decrypt struct {
	// 服务端加密，客户端解密？
	Stoc   bool
	blocks map[string][]byte
}

func (d *Decrypt) AddKeyBase64(version, platform string, b64Key string) error {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return err
	}
	return d.AddKey(version, platform, key)
}

// AddKey add a key with version and platform. Key length must be 32. This method
// can be call many times to add more keys with different version or different platform.
func (d *Decrypt) AddKey(version, platform string, key []byte) error {
	version = strings.ToLower(version)
	platform = strings.ToLower(platform)
	if len(key) != 32 {
		return ErrKeyLenWrong
	}
	if d.blocks == nil {
		d.blocks = map[string][]byte{}
	}
	if _, ok := d.blocks[version+"|"+platform]; ok {
		log.Printf("overwrited version=%s and platform=%s key exist", version, platform)
	}
	d.blocks[version+"|"+platform] = key
	return nil
}

// Decrypt 解密，返回版本、平台、通用参数和明文。注意此方法是就地解密的，会改变入参
func (d *Decrypt) Decrypt(data []byte) (version, platform, params string, plain []byte, err error) {
	sign, annex, ciphertext, err := split(data)
	if err != nil {
		return "", "", "", nil, err
	}

	var enc string
	version, platform, enc, params, err = unmarshal(annex)
	if err != nil {
		return "", "", "", nil, err
	}

	var iv []byte
	var block cipher.Block

	if enc == "" {
		iv, ciphertext, block, err = d.Decrypt1(version, platform, params, sign, ciphertext)
	} else if enc == "1" {
		iv, ciphertext, block, err = d.Decrypt2(version, platform, params, sign, ciphertext)
	} else {
		return "", "", "", nil, ErrEncWrong
	}

	plain, err = aesDecrypt(iv, ciphertext, block)
	return version, platform, params, plain, err
}

// Decrypt 解密，返回版本、平台、通用参数和明文。注意此方法是就地解密的，会改变入参
func (d *Decrypt) DecryptApp(appID string, data []byte) (version, platform, params string, plain []byte, err error) {
	sign, annex, ciphertext, err := split(data)
	if err != nil {
		return "", "", "", nil, err
	}

	var enc string
	version, platform, enc, params, err = unmarshal(annex)
	if err != nil {
		return "", "", "", nil, err
	}
	platform = platform + "|" + appID

	var iv []byte
	var block cipher.Block

	if enc == "" {
		iv, ciphertext, block, err = d.Decrypt1(version, platform, params, sign, ciphertext)
	} else if enc == "1" {
		iv, ciphertext, block, err = d.Decrypt2(version, platform, params, sign, ciphertext)
	} else {
		return "", "", "", nil, ErrEncWrong
	}

	plain, err = aesDecrypt(iv, ciphertext, block)
	return version, platform, params, plain, err
}

func split(data []byte) (sign, annex, cipher []byte, err error) {
	const dot = '.'
	idx := bytes.IndexByte(data, dot)
	if idx == -1 {
		return nil, nil, nil, ErrDotPartsWrong
	}
	sign = data[:idx]
	data = data[idx+1:]
	idx = bytes.IndexByte(data, dot)
	if idx == -1 {
		return nil, nil, nil, ErrDotPartsWrong
	}
	return sign, data[:idx], data[idx+1:], nil
}

var (
	groupSep = []byte{0x1E}
	unitSep  = []byte{0x1F}
)

func unmarshal(annex []byte) (version, platfom, enc, param string, err error) {
	origin, err := base64.StdEncoding.DecodeString(string(annex))
	if err != nil {
		return "", "", "", "", err
	}
	groups := bytes.Split(origin, groupSep)
	if len(groups) < 3 {
		return "", "", "", "", ErrGroupsNotEnough
	}

	for _, v := range groups {
		units := bytes.Split(v, unitSep)
		if len(units) != 2 {
			return "", "", "", "", ErrUnitsNotEnough
		}

		switch string(units[0]) {
		case "version":
			version = string(units[1])
		case "platform":
			platfom = string(units[1])
		case "param":
			param = string(units[1])
		case "ec":
			enc = string(units[1])
		default:
			return "", "", "", "", ErrUnsupportedUnit
		}
	}

	return version, platfom, enc, param, nil
}

func aesDecrypt(iv, ciphertext []byte, block cipher.Block) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrCipherLenWrong
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)
	return pkcs7UnPadding(aes.BlockSize, ciphertext)
}

func pkcs7UnPadding(blockSize int, data []byte) ([]byte, error) {
	l := len(data)
	un := data[l-1]
	if un > byte(blockSize) {
		return nil, ErrPaddingWrong
	}
	s := l - int(un)
	for i, e := s, l-1; i < e; i++ {
		if data[i] != un {
			return nil, ErrPaddingWrong
		}
	}
	return data[:s], nil
}
