//
// Copyright 2017 Tink AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

type Crypto interface {
	Encrypt(b []byte) []byte
	Decrypt(sne []byte) ([]byte, error)
}

type StdCrypto struct {
	aesKey  []byte
}

func (c *StdCrypto) Encrypt(b []byte) []byte {
	// Encrypt payload b using AES.
	// The output format is:
	// AES([nonce] [plaintext])
	bs := aes.BlockSize
	nonce := make([]byte, bs)
	rand.Read(nonce)
	a, err := aes.NewCipher(c.aesKey)
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize AES: %s", err))
	}
	ci := cipher.NewCBCEncrypter(a, nonce)

	// Pad b to block size as bPad
	p := bs - (len(b) % bs)
	bp := len(b) + p
	bPad := make([]byte, bp)
	copy(bPad, b)
	for i := len(b); i < bp; i++ {
		bPad[i] = byte(p)
	}

	e := make([]byte, bp)
	ci.CryptBlocks(e, bPad)
	return append(nonce, e...)
}

func (c *StdCrypto) Decrypt(ne []byte) ([]byte, error) {
	bs := aes.BlockSize
	nonce := ne[:bs]
	e := ne[bs:]

	a, err := aes.NewCipher(c.aesKey)
	if err != nil {
		panic(fmt.Sprintf("Unable to initialize AES: %s", err))
	}
	ci := cipher.NewCBCDecrypter(a, nonce)

	bp := len(e)
	bPad := make([]byte, bp)
	ci.CryptBlocks(bPad, e)

	// Remove (and sanity check) padding
	p := int(bPad[len(bPad)-1])
	pad := bPad[len(bPad)-p:]
	b := bPad[:len(bPad)-p]

	for _, x := range pad {
		if int(x) != p {
			return nil, errors.New("decryption failed")
		}
	}
	return b, nil
}

func NewStdCrypto(aes []byte) *StdCrypto {
	c := StdCrypto{}
	if len(aes) != 32 {
		// Require use of AES-256
		panic("AES key must be 32 bytes")
	}
	c.aesKey = aes
	return &c
}
