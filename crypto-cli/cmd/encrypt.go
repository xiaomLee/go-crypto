/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"github.com/jan-bar/EncryptionFile"
	"github.com/spf13/cobra"
	"go-crypto/crypto-cli/utils"
	"hash"
	"io"
	"log"
	"os"
	"reflect"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "加密文件",
	Long: `加密文件
示例:

crypto-cli encrypt --public-key public.key -f your-src.file -o ciphered.file
crypto-cli encrypt -g -f your.file -o ciphered.file
crypto-cli encrypt --public-key public.key --security aes-256-cbc -f your.file -o ciphered.file
`,
	//PreRun: initEncryptor,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[INFO] EncData called")
		EncData(cmd, args)
		log.Println("[INFO] EncData ended")
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func encrypt(cmd *cobra.Command, args []string) {
	defer func() {
		if err := moveOutputFile("ciphered-file.bin"); err != nil {
			log.Printf("[ERROR] moveOutputFile failed: %v output:%s ", err, conf.Out)
		}
	}()
	in, err := os.Open(conf.File)
	if err != nil {
		log.Fatalf("[FATA] open file:%s err:%s", conf.File, err)
	}
	defer in.Close()

	out, err := os.OpenFile("ciphered-file.bin", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("[FATA] open file:%s err:%s", conf.File, err)
	}
	defer out.Close()

	ivBuffer := bufio.NewWriter(out)
	ivBuffer.Write(encryptor.GetIV())
	ivBuffer.WriteString(cipherBlockSep)
	if err := ivBuffer.Flush(); err != nil {
		log.Fatalf("[FATA] write iv into cipher file:%s err:%s", conf.File, err)
	}

	// 每 100 mb 加密一次
	fInfo, _ := in.Stat()
	fLen := fInfo.Size()
	fmt.Println("待处理文件大小:", fLen)
	maxLen := 1024 * 1024 * 100 //100mb  每 100mb 进行加密一次
	var forNum int64 = 0
	getLen := fLen

	if fLen > int64(maxLen) {
		getLen = int64(maxLen)
		forNum = fLen / int64(maxLen)
		fmt.Println("需要加密次数：", forNum+1)
	}

	cipherBuf := make([]byte, getLen)
	for i := 0; i < int(forNum+1); i++ {
		n, err := in.Read(cipherBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("[FATA] read file err:%s", err)
		}
		ciphertext, err := encryptor.Encrypt(cipherBuf[:n])
		if err != nil {
			log.Fatalf("[FATA] encrypt error: %v", err)
		}

		plaintext, err := encryptor.Decrypt(ciphertext)
		if err != nil {
			log.Fatalf("[FATA] decrypt error: %v", err)
		}
		if !reflect.DeepEqual(plaintext, cipherBuf) {
			log.Fatalf("[FATA] decrypt error: not equal original")
		}
		log.Printf("[INFO] encrypted plaintext: %#v", plaintext)

		//换行处理，有点乱了，想到更好的再改
		//写入
		buf := bufio.NewWriter(out)
		buf.Write(ciphertext)
		buf.WriteString(cipherBlockSep)
		if err := buf.Flush(); err != nil {
			log.Fatalf("[FATA] write ciphertext into cipher file error: %v", err)
		}
	}
}

func initEncryptor(cmd *cobra.Command, args []string) {
	encryptor = utils.InitAesEncryptor(&conf)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatalf("[FATA] init encrypt error: %v", err)
	}
	encryptor.SetIV(iv)
	fmt.Println("Encrypt iv: ", iv)
}

func moveOutputFile(tmp string) error {
	if conf.Out != "" {
		return os.Rename(tmp, conf.Out)
	}
	return os.Rename(tmp, conf.File)
}

func EncData(cmd *cobra.Command, args []string) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[FATA] EncData err:%s", err)
			return
		}
		if err := moveOutputFile(conf.File + ".enc"); err != nil {
			log.Printf("[ERROR] moveOutputFile failed: %v output:%s ", err, conf.Out)
		}
	}()

	if !conf.GenerateKey && conf.PublicKey == "" {
		log.Fatalf("[FATA] --generate-key or --key-file must Specify one")
		return
	}

	var pubKey []byte
	var err error
	if conf.PublicKey == "" {
		pubKey, err = os.ReadFile(conf.PublicKey)
		if err != nil {
			log.Fatalf("[FATA] read public key error:%s, key:%s", err, conf.PublicKey)
		}
	} else {
		pubKey, _, err = utils.GenRsaKey()
		if err != nil {
			log.Fatalf("[FATA] GenRsaKey error:%s", err)
		}
	}

	if err := encFile(conf.File, pubKey, md5.New(), utils.InitEncCipher(&conf)); err != nil {
		log.Printf("[ERROR] EncryptionFile EncData err:%s", err)
	}

	//if err := decFile(conf.File, priKey, md5.New(), utils.InitDecCipher(&conf)); err != nil {
	//	log.Printf("[ERROR] Could not decrypt file:%s, err:%v", conf.File, err)
	//}
}

func encFile(f string, pubKey []byte, h hash.Hash, enc EncryptionFile.EncCipher) error {
	fr, err := os.Open(f)
	if err != nil {
		return err
	}
	defer fr.Close()

	fw, err := os.Create(f + ".enc")
	if err != nil {
		return err
	}
	defer fw.Close()

	h.Reset()
	return EncryptionFile.EncData(fr, fw, pubKey, h, enc)
}
