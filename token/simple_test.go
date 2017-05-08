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
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSimpleProvider(t *testing.T) {
	ft := FakeTime{}
	ft.time = time.Now()

	generation := 0
	p := NewSimpleProvider(generation, &ft)
	pn := NewSimpleProvider(generation+1, &ft)

	r := Request{}
	r.User = "test-user"
	r.Domain = "test-domain"
	r.Groups = []string{"test-group1", "test-group2"}
	r.Expiry = time.Now().Add(time.Minute * 15)

	token, err := p.New(r)
	assert.NoError(t, err)

	// Test success
	u, err := p.Validate(token, "test-domain", "test-group2")
	assert.Equal(t, "test-user", u.User)
	assert.NoError(t, err)

	// Test corrupt token
	_, err = p.Validate([]byte("foobar"), "test-d0main", "test-group2")
	assert.Error(t, err)

	// Test domain scope
	_, err = p.Validate(token, "test-d0main", "test-group2")
	assert.Error(t, err)

	// Test group membership
	_, err = p.Validate(token, "test-domain", "test-group3")
	assert.Error(t, err)

	// Test generation revocation
	_, err = pn.Validate(token, "test-domain", "test-group2")
	assert.Error(t, err)

	// Test expiry
	ft.Add(time.Minute*15 + time.Second)
	_, err = p.Validate(token, "test-domain", "test-group2")
	assert.Error(t, err)
}
