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
package provider

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/tstranex/u2f"
)

type U2FStore interface {
	Registrations(user string) ([]*u2f.Registration, error)
	Register(user string, reg u2f.Registration) error
	IncreaseCounter(user string, i int, counter uint32) error
}

type FilesystemU2FStore struct {
	path string
}

type U2FFile struct {
	Registrations []*u2f.Registration
	Counters      []uint32
}

func (s *FilesystemU2FStore) filename(user string) string {
	hash := sha256.Sum256([]byte(user))
	return fmt.Sprintf(s.path, hex.EncodeToString(hash[:]))
}

func (s *FilesystemU2FStore) read(user string) (*U2FFile, error) {
	f, err := os.Open(s.filename(user))
	if err != nil {
		// If the file is not there, it's not an error but just no data available.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	dec := gob.NewDecoder(f)
	var u2ffile U2FFile
	err = dec.Decode(&u2ffile)
	if err != nil {
		return nil, err
	}
	return &u2ffile, nil
}

func (s *FilesystemU2FStore) write(user string, u2ffile *U2FFile) error {
	f, err := os.OpenFile(s.filename(user), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := gob.NewEncoder(f)
	return enc.Encode(u2ffile)
}

func (s *FilesystemU2FStore) Registrations(user string) ([]*u2f.Registration, error) {
	f, err := s.read(user)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return []*u2f.Registration{}, nil
	}
	return f.Registrations, nil
}

func (s *FilesystemU2FStore) Register(user string, reg u2f.Registration) error {
	f, err := s.read(user)
	if err != nil {
		return err
	}
	if f == nil {
		f = &U2FFile{}
	}
	f.Registrations = append(f.Registrations, &reg)
	f.Counters = append(f.Counters, 0)
	return s.write(user, f)
}

func (s *FilesystemU2FStore) IncreaseCounter(user string, i int, c uint32) error {
	f, err := s.read(user)
	if err != nil {
		return err
	}
	if f.Counters[i] > c {
		return errors.New("counter decreased")
	}
	f.Counters[i] = c
	return s.write(user, f)
}

func NewFilesystemU2FStore(path string) *FilesystemU2FStore {
	s := FilesystemU2FStore{}
	s.path = path
	return &s
}
