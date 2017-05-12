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
	"errors"
	log "github.com/Sirupsen/logrus"
	"net/http"

	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/session"
	"github.com/tstranex/u2f"
)

// U2F Authentication request.
type AuthenticateRequest struct {
	SignRequests []u2f.SignRequest `json:"signRequests"`
}

type U2FProvider struct {
	// In-memory map of in-progress U2F challenges
	challenges map[string]*u2f.Challenge

	// Our identification to the browser
	appID string

	// Which applications that are allowed to use our registration
	trustedFacets []string

	// Function to call when a session has been authenticated by this module
	successCallback SuccesCallback

	// Function to find out where to send the user when U2F is done
	nextURLCallback NextURLCallback

	// Storage for U2F registrations
	store U2FStore
}

func (p *U2FProvider) RegisterRequestHandler(c context.Context, s *session.LoginSession) {
	chal, err := u2f.NewChallenge(p.appID, p.trustedFacets)
	if err != nil {
		log.Errorf("u2f new challenge error: %v", err)
		c.Error(http.StatusInternalServerError, errors.New("u2f challenge error"))
		return
	}

	// Save the challenge for validation when the response comes back
	p.challenges[s.SessionID] = chal

	req := chal.RegisterRequest()
	c.JSON(req)
}

func (p *U2FProvider) RegisterResponseHandler(c context.Context, s *session.LoginSession) {
	var regResp u2f.RegisterResponse
	if err := c.BindJSON(&regResp); err != nil {
		log.Warnf("u2f response error: %v", err)
		c.Error(http.StatusInternalServerError, errors.New("u2f response error"))
		return
	}

	// TODO: As this register flow is part of the sign-in flow we only allow
	// the initial registration here. If the user wants to add more devices,
	// a new page requiring a successful login would have to be added.
	// Also, there is a slight race here between the check and the persistence.
	r, err := p.store.Registrations(s.Email)
	if err != nil {
		log.Errorf("Error reading U2F registration for %s: %s", s.Email, err)
		c.Error(http.StatusInternalServerError, errors.New("internal registration data invalid"))
		return
	}
	if len(r) > 0 {
		log.Errorf("SECURITY VIOLATION: User %s tried to add extra U2F device", s.Email)
		c.Error(http.StatusInternalServerError, errors.New("u2f device already registered"))
		return
	}

	// Check that the challenge was the one we gave out
	chal := p.challenges[s.SessionID]
	if chal == nil {
		c.Error(http.StatusBadRequest, errors.New("challenge not found"))
		return
	}

	reg, err := u2f.Register(regResp, *chal, nil)
	if err != nil {
		log.Warnf("u2f register error: %v", err)
		c.Error(http.StatusInternalServerError, errors.New("error verifying response"))
		return
	}

	err = p.store.Register(s.Email, *reg)
	if err != nil {
		log.Errorf("u2f store error: %v", err)
		c.Error(http.StatusInternalServerError, errors.New("error storing registration"))
		return
	}
	c.String("done")
}

func (p *U2FProvider) SignRequestHandler(c context.Context, s *session.LoginSession) {
	r, err := p.store.Registrations(s.Email)
	if err != nil {
		log.Errorf("Error reading U2F registration for %s: %s", s.Email, err)
		c.Error(http.StatusInternalServerError, errors.New("internal registration data invalid"))
		return
	}
	if len(r) == 0 {
		c.Error(http.StatusBadRequest, errors.New("registration missing"))
		return
	}

	chal, err := u2f.NewChallenge(p.appID, p.trustedFacets)
	if err != nil {
		log.Errorf("u2f new challenge error: %v", err)
		c.Error(http.StatusInternalServerError, errors.New("registration missing"))
		return
	}

	// Save the challenge for validation when the response comes back
	p.challenges[s.SessionID] = chal

	var req AuthenticateRequest
	for _, reg := range r {
		sr := chal.SignRequest(*reg)
		req.SignRequests = append(req.SignRequests, *sr)
	}
	c.JSON(req)
}

func (p *U2FProvider) SignResponseHandler(c context.Context, s *session.LoginSession) {
	var signResp u2f.SignResponse
	if err := c.BindJSON(&signResp); err != nil {
		c.Error(http.StatusBadRequest, errors.New("u2f response invalid"))
		return
	}

	// Check that the challenge was the one we gave out
	chal := p.challenges[s.SessionID]
	if chal == nil {
		c.Error(http.StatusBadRequest, errors.New("challenge missing"))
		return
	}

	r, err := p.store.Registrations(s.Email)
	if err != nil {
		log.Warnf("Error reading U2F registration for %s: %s", s.Email, err)
		c.Error(http.StatusInternalServerError, errors.New("internal registration data invalid"))
		return
	}

	if len(r) == 0 {
		c.Error(http.StatusBadRequest, errors.New("registration missing"))
		return
	}

	for i, reg := range r {
		cntr, err := (*reg).Authenticate(signResp, *chal, uint32(0))
		if err == nil {
			err := p.store.IncreaseCounter(s.Email, i, cntr)
			if err != nil {
				log.Errorf("Error storing counter increment for %s: %s", s.Email, err)
				c.Error(http.StatusBadRequest, errors.New("error validating device counter"))
				continue
			}
			s.PresenceValidated = true
			if p.successCallback != nil {
				p.successCallback(c, s)
			}
			c.String("ok")
			return
		}
	}
	c.Error(http.StatusUnauthorized, errors.New("error verifying response"))
}

func (p *U2FProvider) Handler(c context.Context, s *session.LoginSession) {
	if s.Used {
		// Authentication succeeded
		c.Redirect(p.nextURLCallback(s))
		return
	}

	template := "u2f-sign.tmpl"
	r, err := p.store.Registrations(s.Email)
	if err != nil {
		log.Errorf("Error reading U2F registration for %s: %s", s.Email, err)
		c.Error(http.StatusInternalServerError, errors.New("internal registration data invalid"))
		return
	}
	if len(r) == 0 {
		template = "u2f-registration.tmpl"
	}

	c.HTML(template, context.H{
		"name":   s.Name,
		"email":  s.Email,
		"domain": s.Domain,
		"state":  s.SessionID,
	})
}

func NewU2F(appID string, trustedFacets []string, store U2FStore, successCallback SuccesCallback, nextURLCallback NextURLCallback) *U2FProvider {
	p := U2FProvider{}
	p.challenges = make(map[string]*u2f.Challenge)
	p.appID = appID
	p.trustedFacets = trustedFacets
	p.store = store
	p.successCallback = successCallback
	p.nextURLCallback = nextURLCallback
	return &p
}
