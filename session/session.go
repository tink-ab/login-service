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
package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tink-ab/login-service/context"
)

type LoginSession struct {
	Expiry        time.Time
	SessionID     string
	ClientMark    string
	Domain        string
	RequiredGroup string

	Email  string
	Name   string
	Groups []string

	PresenceValidated bool

	RedirectURL string
	U2FURL      string

	Used bool
}

// Ongoing login sessions
var loginSessions map[string]*LoginSession
var sessionMutex sync.RWMutex

func newNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func New(c context.Context, ttl time.Duration, fallback string, u2furl string, allowedDomain string, group string) *LoginSession {
	s := LoginSession{}
	s.SessionID = newNonce()
	s.ClientMark = c.ClientMark()
	s.Domain = c.Query("d")
	s.RequiredGroup = group
	s.Expiry = time.Now().Add(ttl)

	r := c.Query("r")
	if r == "" {
		s.RedirectURL = fallback
	} else {
		ru, err := url.Parse(r)
		if err != nil {
			c.Error(http.StatusBadRequest, errors.New("invalid redirect url"))
			return nil
		}
		if !strings.HasSuffix(ru.Host, allowedDomain) {
			c.Error(http.StatusBadRequest, errors.New("invalid redirect url"))
			return nil
		}
		if ru.Scheme != "https" {
			c.Error(http.StatusBadRequest, errors.New("invalid redirect url"))
			return nil
		}
		s.RedirectURL = r
	}

	s.U2FURL = fmt.Sprintf(u2furl, s.SessionID)

	if s.Domain == "" || s.RequiredGroup == "" {
		c.Error(http.StatusBadRequest, errors.New("invalid domain"))
		return nil
	}

	sessionMutex.Lock()
	loginSessions[s.SessionID] = &s
	sessionMutex.Unlock()

	return &s
}

func Wrap(rh func(context.Context, *LoginSession)) func(context.Context) {
	return func(c context.Context) {
		sessionMutex.RLock()
		s := loginSessions[c.SessionID()]
		sessionMutex.RUnlock()
		if s == nil || s.Expiry.Before(time.Now()) {
			c.Error(http.StatusUnauthorized, errors.New("login session expired"))
			return
		}
		if s.ClientMark != c.ClientMark() {
			log.Errorf("got session with mismatching client mark")
			c.Error(http.StatusUnauthorized, errors.New("login session expired"))
			return
		}
		rh(c, s)
	}
}

func init() {
	loginSessions = make(map[string]*LoginSession)
}
