package utils

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"github.com/jan-bar/EncryptionFile"
	"go-crypto/aes"
	"go-crypto/crypto-cli/config"
	"log"
	"os"
	"strconv"
	"strings"
)

func InitAesEncryptor(conf *config.Config) *aes.Encryptor {
	var (
		err         error
		keyStrBytes []byte
		mode        aes.Mode
	)
	if strings.HasPrefix(conf.PrivateKey, "@") {
		// read from file
		keyStrBytes, err = os.ReadFile(strings.TrimPrefix(conf.PrivateKey, "@"))
		if err != nil {
			log.Fatalf("[FATA] Could not read key file:%s", err)
		}
	} else {
		keyStrBytes = []byte(conf.PrivateKey)
	}
	//fmt.Println("keyStrBytes", keyStrBytes)
	key := make([]byte, hex.EncodedLen(len(keyStrBytes)))
	hex.Encode(key, keyStrBytes)

	securities := strings.Split(conf.Security, "-")
	if len(securities) != 3 {
		log.Fatalf("[FATA] Could not resoval security:%s", conf.Security)
	}
	keyLen, err := strconv.ParseInt(securities[1], 10, 64)
	if err != nil {
		log.Fatalf("[FATA] Could not resoval security:%s", conf.Security)
	}
	key = repeat(key, int(keyLen)/8)
	//fmt.Printf("key:%s", string(key))
	mode = aes.Mode(strings.ToUpper(securities[2]))

	return aes.NewEncryptor(key, mode)
}

func repeat(src []byte, size int) []byte {
	if len(src) >= size {
		return src[:size]
	}
	dst := make([]byte, size)
	m := size / len(src)
	n := size % len(src)
	i := 0
	for ; i < m; i++ {
		copy(dst[i*len(src):], src)
	}
	copy(dst[m*len(src):], src[:n])
	return dst
}

func GenRsaKey() (pubKey, priKey []byte, err error) {
	bufLen := 32 * 1024
	bufLen2 := 2 * bufLen
	var (
		tmpBuf0 = bytes.NewBuffer(make([]byte, 0, bufLen2))
		tmpBuf1 = bytes.NewBuffer(make([]byte, 0, bufLen2))
	)

	err = EncryptionFile.GenRsaKey(0, tmpBuf0, tmpBuf1)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	priKey = make([]byte, tmpBuf1.Len())
	pubKey = make([]byte, tmpBuf0.Len())
	copy(priKey, tmpBuf1.Bytes()) // save the private key
	copy(pubKey, tmpBuf0.Bytes()) // save the public key
	privateFile, err := os.OpenFile("private.key", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	defer privateFile.Close()
	publicFile, err := os.OpenFile("public.key", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}
	defer publicFile.Close()

	if _, err := privateFile.Write(priKey); err != nil {
		log.Println(err)
		return nil, nil, err
	}
	if _, err := publicFile.Write(pubKey); err != nil {
		log.Println(err)
		return nil, nil, err
	}
	return
}

func InitEncCipher(c *config.Config) EncryptionFile.EncCipher {
	securities := strings.Split(c.Security, "-")
	if len(securities) != 3 {
		log.Fatalf("[FATA] Could not resoval security:%s", c.Security)
	}
	switch aes.Mode(strings.ToUpper(securities[2])) {
	case aes.ModeCBC:
		return EncryptionFile.GenEncCipher(cipher.NewCBCEncrypter)
	case aes.ModeCFB:
		return EncryptionFile.GenEncCipher(cipher.NewCFBEncrypter)
	case aes.ModeCTR:
		return EncryptionFile.GenEncCipher(cipher.NewCTR)
	case aes.ModeOFB:
		return EncryptionFile.GenEncCipher(cipher.NewOFB)
	default:
		log.Fatalf("[FATA] invalid security mode:%s", c.Security)
		return nil
	}
}

func InitDecCipher(c *config.Config) EncryptionFile.DecCipher {
	securities := strings.Split(c.Security, "-")
	if len(securities) != 3 {
		log.Fatalf("[FATA] Could not resoval security:%s", c.Security)
	}
	switch aes.Mode(strings.ToUpper(securities[2])) {
	case aes.ModeCBC:
		return EncryptionFile.GenDecCipher(cipher.NewCBCDecrypter)
	case aes.ModeCFB:
		return EncryptionFile.GenDecCipher(cipher.NewCFBEncrypter)
	case aes.ModeCTR:
		return EncryptionFile.GenDecCipher(cipher.NewCTR)
	case aes.ModeOFB:
		return EncryptionFile.GenDecCipher(cipher.NewOFB)
	default:
		log.Fatalf("[FATA] invalid security mode:%s", c.Security)
		return nil
	}
}
