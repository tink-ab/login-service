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
	"encoding/json"
	"errors"
)

type SimpleProvider struct {
	generation int
	time       Time
}

type SimpleToken struct {
	Request    Request
	Generation int
}

func (p *SimpleProvider) New(req Request) ([]byte, error) {
	t := SimpleToken{}
	t.Request = req
	t.Generation = p.generation
	v, err := json.Marshal(t)
	return v, err
}

func (p *SimpleProvider) Validate(token []byte, domain string, group string) (*Request, error) {
	var t SimpleToken
	err := json.Unmarshal(token, &t)
	if err != nil {
		return nil, err
	}
	if t.Generation < p.generation {
		return nil, errors.New("token generation expired")
	}
	if t.Request.Expiry.Before(p.time.Now()) {
		return nil, errors.New("token expired")
	}
	if t.Request.Domain != domain {
		return nil, errors.New("token domain mismatch")
	}
	for _, g := range t.Request.Groups {
		if g == group {
			return &t.Request, nil
		}
	}
	return nil, errors.New("token not valid for group")
}

func NewSimpleProvider(generation int, time Time) *SimpleProvider {
	p := SimpleProvider{}
	p.generation = generation
	p.time = time
	return &p
}
