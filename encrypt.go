package cipherlib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
)

type Encrypt struct {
	// 服务端加密，客户端解密？
	Stoc bool
	keys map[string][]byte
}

func (enc *Encrypt) AddKeyBase64(version, platform string, b64Key string) error {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return err
	}
	return enc.AddKey(version, platform, key)
}

func (enc *Encrypt) AddKey(version, platform string, key []byte) error {
	if len(key) != 32 {
		return ErrKeyLenWrong
	}
	version = strings.ToLower(version)
	platform = strings.ToLower(platform)

	if enc.keys == nil {
		enc.keys = map[string][]byte{}
	}
	if _, ok := enc.keys[version+"|"+platform]; ok {
		log.Printf("overwrited version=%s and platform=%s key exist", version, platform)
	}
	enc.keys[version+"|"+platform] = key
	return nil
}

func (e *Encrypt) marshal(version, platform, param, ec string) string {
	var buf bytes.Buffer
	buf.WriteString("param")
	buf.Write(unitSep)
	buf.WriteString(param)
	buf.Write(groupSep)
	buf.WriteString("version")
	buf.Write(unitSep)
	buf.WriteString(version)
	buf.Write(groupSep)
	buf.WriteString("platform")
	buf.Write(unitSep)
	buf.WriteString(platform)
	if ec != "" {
		buf.Write(groupSep)
		buf.WriteString("ec")
		buf.Write(unitSep)
		buf.WriteString(ec)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func aesEncrypt(plain, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := pkcs7Padding(aes.BlockSize, plain)
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func pkcs7Padding(blockSize int, plain []byte) []byte {
	pad := blockSize - len(plain)%blockSize
	return append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func signature(ciphertext []byte, param string) string {
	h := md5.New()
	h.Write(ciphertext)
	fmt.Fprint(h, param)
	return fmt.Sprintf("%02X", h.Sum(nil))
}
