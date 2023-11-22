package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Mode 加密模式
// ECB: 电码本模式（Electronic Codebook Book）
// CBC: 密码分组链接模式（Cipher Block Chaining）
// CTR: 计算器模式（Counter）
// CFB: 密码反馈模式（Cipher FeedBack）
// OFB: 输出反馈模式（Output FeedBack）
type Mode string

const (
	ModeECB Mode = "ECB"
	ModeCBC Mode = "CBC"
	ModeCTR Mode = "CTR"
	ModeCFB Mode = "CFB"
	ModeOFB Mode = "OFB"
)

type Encryptor struct {
	key  []byte
	iv   []byte
	mode Mode
}

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// 分组秘钥
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("key 长度必须 16/24/32长度: %s", err.Error())
	}
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补码
	plaintext = PKCS7Padding(plaintext, blockSize)
	ciphertext := make([]byte, len(plaintext))

	// 加密
	switch e.mode {
	case ModeECB:
		// ECB 模式比较特别没有用到初始向量 IV
		// ECB 是把整个明文分成若干段相同的小段，然后对每一小段进行加密
		for bs, be := 0, blockSize; bs < len(plaintext); bs, be = bs+blockSize, be+blockSize {
			block.Encrypt(ciphertext[bs:be], plaintext[bs:be])
		}
	case ModeCBC:
		blockMode := cipher.NewCBCEncrypter(block, e.iv[:blockSize])
		blockMode.CryptBlocks(ciphertext, plaintext)
	case ModeCTR:
		ctr := cipher.NewCTR(block, e.iv[:blockSize])
		ctr.XORKeyStream(ciphertext, plaintext)
	case ModeCFB:
		cfb := cipher.NewCFBEncrypter(block, e.iv[:blockSize])
		cfb.XORKeyStream(ciphertext, plaintext)
	case ModeOFB:
		ofb := cipher.NewOFB(block, e.iv[:blockSize])
		ofb.XORKeyStream(ciphertext, plaintext)
	default:
		return nil, fmt.Errorf("invalid encrypt mode: %s", e.mode)
	}

	return ciphertext, nil
}

func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	// 分组秘钥
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("key 长度必须 16/24/32长度: %s", err.Error())
	}
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	iv := e.iv[:blockSize]

	// 创建数组
	plaintext := make([]byte, len(ciphertext))

	// 加密模式 解密
	switch e.mode {
	case ModeECB:
		// ECB 模式没有用到初始向量IV
		// ECB 是把整个明文分成若干段相同的小段，然后对每一小段进行加密
		for bs, be := 0, blockSize; bs < len(ciphertext); bs, be = bs+blockSize, be+blockSize {
			block.Decrypt(plaintext[bs:be], ciphertext[bs:be])
		}
	case ModeCBC:
		blockMode := cipher.NewCBCDecrypter(block, iv)
		blockMode.CryptBlocks(plaintext, ciphertext)
	case ModeCTR:
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(plaintext, ciphertext)
	case ModeCFB:
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(plaintext, ciphertext)
	case ModeOFB:
		ofb := cipher.NewOFB(block, iv)
		ofb.XORKeyStream(plaintext, ciphertext)
	default:
		return nil, fmt.Errorf("invalid decrypt mode: %s", e.mode)
	}

	// 去码返回
	return PKCS7UnPadding(plaintext), nil
}

func (e *Encryptor) GetIV() []byte {
	return e.iv
}

func (e *Encryptor) SetIV(iv []byte) error {
	if len(iv) < aes.BlockSize {
		return fmt.Errorf("iv length less than aes.BlockSize, iv:%d", len(iv))
	}
	e.iv = iv[:aes.BlockSize]
	return nil
}

func NewEncryptor(key []byte, mode Mode) *Encryptor {
	return &Encryptor{
		key:  key,
		mode: mode,
	}
}

// PKCS7Padding 补码
func PKCS7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padText...)
}

// PKCS7UnPadding 去码
func PKCS7UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	padding := int(plaintext[length-1])
	return plaintext[:(length - padding)]
}
