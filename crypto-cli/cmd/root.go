/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"go-crypto/aes"
	"go-crypto/crypto-cli/config"
	"go-crypto/version"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const cipherBlockSep = "datacloak-cipher-block-separator"

var conf config.Config
var encryptor *aes.Encryptor

var ciphers = map[string]struct{}{
	"aes-256-ecb": {},
	"aes-256-cbc": {},
	"aes-256-ctr": {},
	"aes-256-cfb": {},
	"aes-256-ofb": {},
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     version.App,
	Version: version.FullVersionInfo(),
	Short:   "文件加解密工具",
	Long: fmt.Sprintf(`文件加解密工具.
原理: 
参考 HTTPS, 原始数据库使用对称加密算法 AES 进行加密, AES 所使用的密钥通过非对称加密算法 RSA 进行加密并存储于原始加密数据的头部;
通过 HASH(MD5) 算法支持文件自校验.

使用示例:
%s encrypt --public-key public.key -f your-src.file 使用指定公钥加密文件，加密后的文件直接覆盖原文件
%s encrypt --public-key public.key -f your-src.file -o ciphered.file 使用指定公钥加密文件，加密后的文件不覆盖原文件
%s encrypt -g -f your.file -o ciphered.file	自动生成密钥对并加密文件
%s encrypt --public-key public.key --security aes-256-cbc -f your.file -o ciphered.file 使用指定公钥与加密算法
%s decrypt --private-key private.key -f your-src.file 使用指定私钥解密指定文件，并覆盖原文件
%s decrypt --private-key private.key -f your-src.file -o unciphered.file 使用指定私钥解密指定文件，不覆盖原文件`,
		version.App, version.App, version.App, version.App, version.App, version.App),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		rand.Seed(time.Now().Unix())
		ParseConfig(cmd, args)
		Validate()
	},
	//Run: func(cmd *cobra.Command, args []string) {
	//	InitEncryptor(cmd, args)
	//},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "conf", "", "conf file (default is $HOME/.go-crypto.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().BoolP("generate-key", "g", false, "指定是否自动生成 RSA 密钥对, 加密时可用")
	rootCmd.PersistentFlags().String("public-key", "", `公钥, 若不指定 generate-key, 则加密时必填`)
	rootCmd.PersistentFlags().String("private-key", "", `私钥, 解密时必填`)
	rootCmd.PersistentFlags().StringP("security", "s", "aes-256-cbc", `加密方式, 默认 aes-256-cbc
支持如下方式
aes-256-ecb aes-256-cbc aes-256-ctr aes-256-cbf aes-256-ofb`)
	rootCmd.PersistentFlags().StringP("file", "f", "", `加密/解密的输入文件, 必填`)
	rootCmd.PersistentFlags().StringP("out", "o", "", `加密/解密的输出文件, 不填则默认覆盖原文件`)
	//rootCmd.PersistentFlags().Int32P("nonce", "n", 0, `随机数, 不大于2^32, 不传则系统随机生成`)

	viper.BindPFlags(rootCmd.PersistentFlags())
	//rootCmd.MarkPersistentFlagRequired("key-file")
	rootCmd.MarkPersistentFlagRequired("file")
}

func ParseConfig(cmd *cobra.Command, args []string) {
	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Fatalf("Unable to read Viper options into configuration: %v", err)
	}
	log.Printf("[INFO] conf:%+v", conf)
}

func Validate() {
	if _, ok := ciphers[conf.Security]; !ok {
		log.Fatalf("[FATA] invalid security cipher:%s", conf.Security)
	}
	if _, err := os.Stat(conf.File); err != nil {
		log.Fatalf("[FATA] open file:%s err:%s", conf.File, err)
	}
}
