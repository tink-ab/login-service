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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"math/big"
)

type Signer interface {
	Sign(d []byte) []byte
}

type Verifier interface {
	Verify(d []byte, s []byte) bool
}

type EcdsaSigner struct {
	k *ecdsa.PrivateKey
}

type EcdsaVerifier struct {
	k *ecdsa.PublicKey
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (s *EcdsaSigner) Public() []byte {
	pkix, err := x509.MarshalPKIXPublicKey(s.k.Public())
	if err != nil {
		panic(err)
	}
	return pkix
}

func (s *EcdsaSigner) Sign(d []byte) []byte {
	h := sha256.Sum256(d)
	er, es, err := ecdsa.Sign(rand.Reader, s.k, h[:])
	if err != nil {
		panic(err)
	}

	sig := ecdsaSignature{}
	sig.R = er
	sig.S = es

	v, err := json.Marshal(sig)
	if err != nil {
		panic(err)
	}
	return v
}

func (v *EcdsaVerifier) Verify(d []byte, s []byte) bool {
	h := sha256.Sum256(d)
	var sig ecdsaSignature
	err := json.Unmarshal(s, &sig)
	if err != nil {
		return false
	}

	return ecdsa.Verify(v.k, h[:], sig.R, sig.S)
}

func NewEcdsaSigner(asn1 []byte) *EcdsaSigner {
	s := EcdsaSigner{}
	k, err := x509.ParseECPrivateKey(asn1)
	if err != nil {
		panic(err)
	}
	s.k = k
	return &s
}

func NewEcdsaVerifier(pkix []byte) *EcdsaVerifier {
	v := EcdsaVerifier{}
	k, err := x509.ParsePKIXPublicKey(pkix)
	if err != nil {
		panic(err)
	}
	v.k = k.(*ecdsa.PublicKey)
	return &v
}
