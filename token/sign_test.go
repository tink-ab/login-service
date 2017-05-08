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
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)


const PrivateKey = "MHcCAQEEIGhv4rm9D7Itorz/YsGZlLUlx9XwkbcNVAd1oQs4U+vuoAoGCCqGSM49AwEHoUQDQgAEkk5UQvVDdHaftMbCkxi+dc+UpstInXiyIBZflDpbGPVfkEx2zaP4bkYIyvGnKY/kjpa53Cc/YCL5NUax1BH2uw=="
const PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkk5UQvVDdHaftMbCkxi+dc+UpstInXiyIBZflDpbGPVfkEx2zaP4bkYIyvGnKY/kjpa53Cc/YCL5NUax1BH2uw=="

func TestPublicKey(t *testing.T) {
	prk, _ := base64.StdEncoding.DecodeString(PrivateKey)
	puk, _ := base64.StdEncoding.DecodeString(PublicKey)
	s := NewEcdsaSigner(prk)
	assert.Equal(t, puk, s.Public())
}

func TestSigning(t *testing.T) {
	prk, _ := base64.StdEncoding.DecodeString(PrivateKey)
	puk, _ := base64.StdEncoding.DecodeString(PublicKey)

	s := NewEcdsaSigner(prk)
	v := NewEcdsaVerifier(puk)

	msg := []byte("hello")
	assert.Equal(t, true, v.Verify(msg, s.Sign(msg)))
	assert.Equal(t, false, v.Verify(msg, s.Sign(msg)[:2]))
}
