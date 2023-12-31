package aes

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"reflect"
	"testing"
)

var commonInput = []byte{
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
}

var commonKey128 = []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

var commonKey192 = []byte{
	0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
	0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
}

var commonKey256 = []byte{
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
}

var commonIV = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}

func TestPKCS7Padding(t *testing.T) {
	type args struct {
		plaintext []byte
		blockSize int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "less-than-blockSize",
			args: args{
				plaintext: []byte{
					0x1, 0x2, 0x3, 0x4, 0x5,
				},
				blockSize: 10,
			},
			want: []byte{
				0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5,
			},
		}, {
			name: "equal-blockSize",
			args: args{
				plaintext: []byte{
					0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
				},
				blockSize: 10,
			},
			want: []byte{
				0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
				0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
			},
		}, {
			name: "bigger-than-blockSize",
			args: args{
				plaintext: []byte{
					0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
					0x1, 0x2, 0x3, 0x4, 0x5,
				},
				blockSize: 10,
			},
			want: []byte{
				0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
				0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS7Padding(tt.args.plaintext, tt.args.blockSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS7Padding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPKCS7UnPadding(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "less-than-blockSize",
			args: args{
				plaintext: []byte{
					0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5,
				},
			},
			want: []byte{
				0x1, 0x2, 0x3, 0x4, 0x5,
			},
		}, {
			name: "equal-blockSize",
			args: args{
				plaintext: []byte{
					0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
					0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
				},
			},
			want: []byte{
				0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
			},
		}, {
			name: "bigger-than-blockSize",
			args: args{
				plaintext: []byte{
					0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
					0x1, 0x2, 0x3, 0x4, 0x5, 0x5, 0x5, 0x5, 0x5, 0x5,
				},
			},
			want: []byte{
				0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
				0x1, 0x2, 0x3, 0x4, 0x5,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS7UnPadding(tt.args.plaintext); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS7UnPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncryptor(t *testing.T) {
	keys := map[string][]byte{
		"aes-128": commonKey128,
		"aes-192": commonKey192,
		"aes-256": commonKey256,
	}
	modes := []Mode{ModeECB, ModeCBC, ModeOFB, ModeCTR, ModeCFB}
	ivs := map[string][]byte{
		"commonIV": commonIV,
		"equalBlockSize": []byte{
			0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
			0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
		},
		"lessBlockSize": []byte{
			0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
		},
		"gtBlockSize": []byte{
			0x1, 0x2, 0x3, 0x4, 0x5, 0xa, 0xb, 0xc, 0xd, 0xe,
			0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
			0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa, 0xa,
		},
	}

	for k, v := range keys {
		for _, mode := range modes {
			for ivName, iv := range ivs {
				t.Run(fmt.Sprintf("%s-%s-%s", k, mode, ivName), func(t *testing.T) {
					e := NewEncryptor(v, mode)
					iv = PKCS7Padding(iv, aes.BlockSize)
					if err := e.SetIV(iv); err != nil {
						t.Fatalf("SetIV() failed: %v", err)
					}
					ciphertext, err := e.Encrypt(commonInput)
					if err != nil {
						t.Errorf("Encrypt() error = %v", err)
						return
					}
					if bytes.Equal(ciphertext, commonInput) {
						t.Errorf("Encrypt() ciphertext = %v equal plaintext = %v", ciphertext, commonInput)
					}
					plaintext, err := e.Decrypt(ciphertext)
					if err != nil {
						t.Errorf("Decrypt() error = %v", err)
						return
					}
					if !bytes.Equal(plaintext, commonInput) {
						t.Errorf("Decrypt() plaintext = %v, want %v", plaintext, commonInput)
					}
				})
			}

		}

	}
}
