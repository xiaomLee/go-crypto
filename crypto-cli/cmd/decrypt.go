/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"fmt"
	"github.com/jan-bar/EncryptionFile"
	"go-crypto/crypto-cli/utils"
	"hash"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "解密文件",
	Long: `使用私钥解密文件. 
示例:

crypto-cli decrypt --private-key private.key -f your-src.file -o unciphered.file`,
	//PreRun: initDecryptor,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("[INFO] decrypt called")
		DecData(cmd, args)
		log.Println("[INFO] decrypt ended")
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// decryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func decrypt(cmd *cobra.Command, args []string) {
	in, err := os.Open(conf.File)
	if err != nil {
		log.Fatalf("[FATA] open file:%s err:%s", conf.File, err)
	}
	defer in.Close()

	out, err := os.OpenFile("plaintext.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	defer out.Close()

	num := 0
	//逐行读取密文，进行解密，写入文件
	br := bufio.NewReader(in)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[ERROR] read file err:%s", err)
			continue
		}
		// skip iv
		if num == 0 {
			num++
			continue
		}
		log.Printf("[INFO] buf:%#v", line)
		plaintext, err := encryptor.Decrypt(bytes.TrimSuffix(line, []byte("\n")))
		if err != nil {
			log.Fatalf("[FATA] decrypt error: %v", err)
		}
		log.Printf("[INFO] plaintext:%#v", plaintext)
		if _, err := out.Write(plaintext); err != nil {
			log.Fatalf("[FATA] write plaintext into cipher file error: %v", err)
		}
		num++
	}
}

func initDecryptor(cmd *cobra.Command, args []string) {
	encryptor = utils.InitAesEncryptor(&conf)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	file, err := os.Open(conf.File)
	defer file.Close()
	if err != nil {
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(file, iv); err != nil {
		log.Fatalf("[FATA] init encrypt error: %v", err)
	}
	encryptor.SetIV(iv)
	fmt.Println("Decrypt iv: ", iv)
}

func DecData(cmd *cobra.Command, args []string) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[FATA] DecData err:%s", err)
			return
		}
		if err := moveOutputFile(conf.File + ".dec"); err != nil {
			log.Printf("[ERROR] moveOutputFile failed: %v output:%s ", err, conf.Out)
		}
	}()

	// read from file
	priKey, err := os.ReadFile(strings.TrimPrefix(conf.PrivateKey, "@"))
	if err != nil {
		log.Fatalf("[FATA] Could not read private key file:%s", err)
	}
	if err := decFile(conf.File, priKey, md5.New(), utils.InitDecCipher(&conf)); err != nil {
		log.Printf("[ERROR] Could not decrypt file:%s, err:%v", conf.File, err)
	}
}

func decFile(f string, priKey []byte, h hash.Hash, dec EncryptionFile.DecCipher) error {
	fr, err := os.Open(f)
	if err != nil {
		return err
	}
	defer fr.Close()

	fw, err := os.Create(f + ".dec")
	if err != nil {
		return err
	}
	defer fw.Close()

	h.Reset()
	return EncryptionFile.DecData(fr, fw, priKey, h, dec)
}
