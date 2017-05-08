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
	"encoding/json"
	"errors"
	"io/ioutil"
	log "github.com/Sirupsen/logrus"
	"net/http"

	"github.com/tink-ab/tink-login-service/context"
	"github.com/tink-ab/tink-login-service/session"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/admin/directory/v1"
)

// User is a retrieved and authentiacted user.
type User struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Profile       string `json:"profile"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Gender        string `json:"gender"`
}

type OAuthSettings struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type ServiceAccount struct {
	Email            string
	PrivateKey       string
	ImpersonateAdmin string
}

type OAuthProvider struct {
	// Client-driven OAuth configuration (for login)
	oauth *oauth2.Config

	// Server-to-server communication (group lookup)
	adminService *admin.Service

	// Function to call when a session has been authenticated by this module
	successCallback SuccesCallback

	// Function to find out where to send the user when U2F is done
	nextURLCallback NextURLCallback
}

func (p *OAuthProvider) getGroups(email string) ([]string, error) {
	g, err := p.adminService.Groups.List().UserKey(email).Do()
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, group := range g.Groups {
		if !group.AdminCreated {
			continue
		}
		groups = append(groups, group.Email)
	}
	log.Debugf("%s is member of %v", email, groups)
	return groups, nil
}

func (p *OAuthProvider) Login(c context.Context, s *session.LoginSession) {
	c.Redirect(p.oauth.AuthCodeURL(s.SessionID))
}

func (p *OAuthProvider) CallbackHandler(c context.Context, s *session.LoginSession) {
	tok, err := p.oauth.Exchange(oauth2.NoContext, c.Query("code"))
	if err != nil {
		log.Printf("oauth token invalid: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}

	client := p.oauth.Client(oauth2.NoContext, tok)
	email, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Errorf("oauth userinfo request failed: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}
	defer email.Body.Close()
	data, _ := ioutil.ReadAll(email.Body)

	var user User
	err = json.Unmarshal(data, &user)
	if err != nil {
		log.Errorf("Failed to deserialize json: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}
	log.Debugf("Got user data: %s", string(data))

	// Sanity check results
	if user.Email == "" {
		log.Errorf("Failed user sanity check")
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}

	// We now known things about the user
	s.Name = user.Name
	s.Email = user.Email
	groups, err := p.getGroups(s.Email)
	if err != nil {
		log.Errorf("Failed to get groups: %s", err)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}
	s.Groups = groups

	// Check if the user is a member of the required group
	found := false
	for _, group := range groups {
		if group == s.RequiredGroup {
			found = true
			break
		}
	}
	if !found {
		log.Printf("user is not member of required group %s", s.RequiredGroup)
		c.Error(http.StatusForbidden, errors.New("user not authorized"))
		return
	}

	if p.successCallback != nil {
		p.successCallback(c, s)
	}

	c.Redirect(p.nextURLCallback(s))
}

func NewOAuth(sa ServiceAccount, oa OAuthSettings, successCallback SuccesCallback, nextURLCallback NextURLCallback) *OAuthProvider {
	p := OAuthProvider{}

	// Admin client used for server-to-server communication
	scope := admin.AdminDirectoryGroupReadonlyScope
	cfg := &jwt.Config{
		Email:      sa.Email,
		PrivateKey: []byte(sa.PrivateKey),
		Scopes:     []string{scope},
		TokenURL:   google.JWTTokenURL,
	}
	cfg.Subject = sa.ImpersonateAdmin
	client := cfg.Client(oauth2.NoContext)
	service, err := admin.New(client)
	if err != nil {
		log.Fatalf("error constructing admin service: %s", err)
	}
	p.adminService = service

	// OAuth2 client used for client driven authentication (login)
	p.oauth = &oauth2.Config{
		ClientID:     oa.ClientID,
		ClientSecret: oa.ClientSecret,
		RedirectURL:  oa.CallbackURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	p.successCallback = successCallback
	p.nextURLCallback = nextURLCallback

	return &p
}
