package utils

import (
	"fmt"
	"go-crypto/crypto-cli/config"
	"reflect"
	"testing"
)

var plaintext = []byte{
	0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5,
}
var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func TestInitAesEncryptor(t *testing.T) {
	type args struct {
		conf *config.Config
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "key-from-str",
			args: args{&config.Config{
				Key:      "adddd",
				Security: "aes-128-cbc",
				File:     "",
				Out:      "",
				Nonce:    0,
			},
			},
		}, {
			name: "key-from-file",
			args: args{&config.Config{
				Key:      "@private.key",
				Security: "aes-256-cbc",
				File:     "",
				Out:      "",
				Nonce:    0,
			},
			},
		}, {
			name: "key-from-file",
			args: args{&config.Config{
				Key:      "aaaaaaddddd",
				Security: "aes-256-cbc",
				File:     "",
				Out:      "",
				Nonce:    0,
			},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Printf("conf:%+v \n", tt.args.conf)
			got := InitAesEncryptor(tt.args.conf)
			if got == nil {
				t.Errorf("InitAesEncryptor() = %v ", got)
			}
			got.SetIV(commonIV)
			ciphertext, err := got.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt error:%v", err)
			}
			decrypttext, err := got.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt error:%v", err)
			}
			if !reflect.DeepEqual(decrypttext, plaintext) {
				t.Errorf("Decrypt text not equal: %v", decrypttext)
			}
		})
	}
}

func Test_repeat(t *testing.T) {
	type args struct {
		src  []byte
		size int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "repeat-0",
			args: args{
				src:  []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
				size: 10,
			},
			want: []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
		}, {
			name: "repeat-1",
			args: args{
				src:  []byte{0x1, 0x2, 0x3, 0x4, 0x5},
				size: 10,
			},
			want: []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
		}, {
			name: "repeat-2",
			args: args{
				src:  []byte{0x1, 0x2, 0x3},
				size: 10,
			},
			want: []byte{0x1, 0x2, 0x3, 0x1, 0x2, 0x3, 0x1, 0x2, 0x3, 0x1},
		}, {
			name: "repeat-3",
			args: args{
				src:  []byte{0x1, 0x2, 0x3, 0x1, 0x2, 0x3, 0x1, 0x2, 0x3, 0x1},
				size: 5,
			},
			want: []byte{0x1, 0x2, 0x3, 0x1, 0x2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := repeat(tt.args.src, tt.args.size); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("repeat() = %v, want %v", got, tt.want)
			}
		})
	}
}
