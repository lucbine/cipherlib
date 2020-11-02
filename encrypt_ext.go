package cipherlib

import "encoding/base64"

type EncryptExt struct {
	version  string
	platform string
	key      []byte
}

func NewEncryptBase64Key(version, platform string, b64Key string) (*EncryptExt, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	return NewEncrypt(version, platform, key)
}

func NewEncrypt(version, platform string, key []byte) (*EncryptExt, error) {
	if len(key) != 32 {
		return nil, ErrKeyLenWrong
	}
	return &EncryptExt{version, platform, key}, nil
}

func (e *EncryptExt) Encrypt(data []byte, param string) ([]byte, error) {
	enc := &Encrypt{Stoc: false}
	enc.AddKey(e.version, e.platform, e.key)
	return enc.Encrypt1(e.version, e.platform, data, param)
}
