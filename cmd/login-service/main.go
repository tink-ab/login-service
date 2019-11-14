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
package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	syslogpkg "log/syslog"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"regexp"

	"gopkg.in/yaml.v2"

	"github.com/gin-gonic/gin"
	"github.com/tink-ab/login-service/context"
	"github.com/tink-ab/login-service/provider"
	"github.com/tink-ab/login-service/session"
	"github.com/tink-ab/login-service/token"
)

var config = flag.String("config", "login-service.yaml", "Configuration file to load")
var static = flag.String("static-dir", "./static", "Directory with static files")
var templates = flag.String("templates-dir", "./templates", "Directory with template files")
var syslogStyle = flag.String("syslog-format", "plain", "Output format of syslog [plain|json]")
var verbose = flag.Bool("verbose", false, "Print debugging messages")

type DomainInfo struct {
	Description string
	Group string
	Downstream string
	GroupPassthroughFilter string
	GroupPassthroughDelimiter string
}

type Settings struct {
	// What scope is the token cookie valid for? (e.g. ".tink.se")
	CookieDomain string
	// How long should the tokens be valid for?
	TokenTTL time.Duration
	// Which token provider to use for new tokens
	DefaultTokenProvider string
	// How long should a login session be allowed to last for?
	LoginSessionTTL time.Duration
	// What URL should the users be redirected to after OAuth?
	U2FURL string
	// What URL should the users be redirected to as a fallback?
	FallbackURL string
	// What domain must the redirect URL end with?
	AllowedRedirectDomain string
	// Token cookie AES key
	TokenAESKey  string
	// Token cookie EC key
	TokenECPrivateKey  string
	// Token generation for mass revoke
	TokenGeneration int

	// Client-driven OAuth configuration
	OAuth provider.OAuthSettings

	// Server-to-server API credentials
	ServiceAccount provider.ServiceAccount

	U2F struct {
		AppID         string
		TrustedFacets []string
		StorePath     string
	}

	DefaultGroupPassthroughDelimiter string
	Domains map[string]DomainInfo

	// User-specific TTLs
	UserTokenTTLs map[string]time.Duration
}

type Time struct{}

// Global login services
var settings Settings
var syslog *log.Logger

// Token handlers
var tokenMinter *token.Minter
var tokenValidator *token.Validator

// Authentication providers
var oauth *provider.OAuthProvider
var u2f *provider.U2FProvider
var clock Time

func (t *Time) Now() time.Time {
	return time.Now()
}

func indexHandler(c context.Context) {
	// Groups are set in the /auth endpoint
	groups := strings.Split(c.Groups(), settings.DefaultGroupPassthroughDelimiter)
	index := make(map[string]DomainInfo)

	// loop through settings.domains and match against groups
	for url, domain := range settings.Domains {
		for _, group := range groups {
			if domain.Group == group {
				index[url] = domain
				break
			}
		}
	}

	c.HTML("index.tmpl", context.H{
		"index":	index,
	})
}

func logoutHandler(c context.Context) {
	// Kill all cookies the client allows us to
	for _, cookie := range c.Cookies() {
		cookie.Value = ""
		cookie.Expires = time.Unix(1, 0)
		cookie.Path = "/"
		cookie.Domain = settings.CookieDomain
		c.SetCookie(cookie)
	}
	c.HTML("logged-out.tmpl", context.H{})
}

func loginHandler(c context.Context) {
	domain := c.Query("d")
	dc, ok := settings.Domains[domain]
	if !ok {
		c.Error(http.StatusBadRequest, errors.New("invalid domain"))
		return
	}

	s := session.New(c, settings.LoginSessionTTL, settings.FallbackURL, settings.U2FURL, settings.AllowedRedirectDomain, dc.Group)
	if s == nil {
		return
	}
	oauth.Login(c, s)
}

func filterDownstreamGroups(currDomain *DomainInfo, request *token.Request) ([]string) {
	// pass through groups to downstream if they match the configured
	// PassthroughFilter for the domain.
	// Return the current domain's group as default.
	groups := []string{currDomain.Group}
	if currDomain.GroupPassthroughFilter == "" {
		return groups
	}

	// anchor the regex
	re, err := regexp.Compile("^" + currDomain.GroupPassthroughFilter + "$")
	if err != nil {
		log.Errorf("The configured regexp is invalid: %s", currDomain.GroupPassthroughFilter)
		return groups
	}

	for _, group := range request.Groups {
		if group != currDomain.Group && re.MatchString(group) {
			groups = append(groups, group)
		}
	}

	return groups
}

func authHandler(c context.Context) {
	// The /auth enpoint accepts cookies through the Authorization HTTP header.
	// As it's in a cookies-type format we will need to re-process it so we can
	// access them in a sensible way.
	cookies := c.Authorization()
	r := fmt.Sprintf("GET / HTTP/1.0\r\nCookie: %s\r\n\r\n", cookies)
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(r)))
	if err != nil {
		c.Error(http.StatusUnauthorized, errors.New("invalid authorization"))
		return
	}

	domain := c.Query("d")
	dc, ok := settings.Domains[domain]
	if !ok {
		// intentional ambiguous error message
		c.Error(http.StatusUnauthorized, errors.New("invalid domain"))
		return
	}

	cookie, err := req.Cookie("Token-" + domain)
	if err != nil {
		c.Error(http.StatusUnauthorized, errors.New("missing token"))
		return
	}

	// Filter away the authentication cookies and leave the ones that we don't
	// manage. This is so the backend will be able to use cookies, but not
	// get access to the token cookies.
	fc := []string{}
	for _, co := range req.Cookies() {
		if strings.HasPrefix(co.Name, "Token-") {
			continue
		}
		fc = append(fc, co.String())
	}

	v, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		c.Error(http.StatusUnauthorized, errors.New("malformed token"))
		return
	}

	request, err := tokenValidator.Validate(v, domain, dc.Group)
	if err == nil {
		downstreamGroups := filterDownstreamGroups(&dc, request)
		delim := settings.DefaultGroupPassthroughDelimiter
		if dc.GroupPassthroughDelimiter != "" {
			delim = dc.GroupPassthroughDelimiter
		}
		c.SetHeader("x-group", strings.Join(downstreamGroups, delim))
		c.SetHeader("x-downstream", dc.Downstream)
		c.SetHeader("x-user", request.User)
		c.SetHeader("x-domain", domain)
		// Pass along the rest of the cookies to pass downstream
		c.SetHeader("x-cookie", strings.Join(fc, ";"))
		c.String("success")
		log.Printf("User %s accessing %s from %s", request.User, domain, c.UserIP())
	} else {
		c.Error(http.StatusUnauthorized, err)
	}
}

func successHandler(c context.Context) {
	// Handler used if we are unable to figure out where to redirect the user
	// after authentication.
	c.HTML("success-no-redirect.tmpl", context.H{})
}

func oauthRedirect(s *session.LoginSession) string {
	return s.U2FURL
}

func u2fRedirect(s *session.LoginSession) string {
	return s.RedirectURL
}

func createToken(c context.Context, s *session.LoginSession) {
	log.Printf("%s: new token request from %s", s.Email, c.UserIP())
	cookie, err := tokenMinter.Create(s)
	if err != nil {
		c.Error(http.StatusInternalServerError, err)
		return
	}

	var expiryTime time.Time

	if duration, ok := settings.UserTokenTTLs[s.Email]; ok {
		log.Printf("%s: Assigning user-specific TTL of %s", s.Email, duration)
		expiryTime = clock.Now().Add(duration)
	} else {
		expiryTime = clock.Now().Add(settings.TokenTTL)
	}

	v := base64.URLEncoding.EncodeToString(cookie)
	hc := http.Cookie{
		Name:     "Token-" + s.Domain,
		Path:     "/",
		Value:    v,
		Expires:  expiryTime,
		Secure:   true,
		HttpOnly: true,
		Domain:   settings.CookieDomain}
	c.SetCookie(&hc)
}

func setup() {
	b, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("Unable to read config: %s", err)
	}

	err = yaml.Unmarshal(b, &settings)
	if err != nil {
		log.Fatalf("Unable to decode config: %s", err)
	}

	providers := make(map[string]token.Provider)
	providers["simple"] = token.NewSimpleProvider(settings.TokenGeneration, &clock)

	aes, err := base64.StdEncoding.DecodeString(settings.TokenAESKey)
	if err != nil {
		log.Fatalf("Unable to decode AES key: %s", err)
	}

	ec, err := base64.StdEncoding.DecodeString(settings.TokenECPrivateKey)
	if err != nil {
		log.Fatalf("Unable to decode EC private key: %s", err)
	}

	crypto := token.NewStdCrypto(aes)
	signer := token.NewEcdsaSigner(ec)
	verifier := token.NewEcdsaVerifier(signer.Public())
	tokenMinter = token.NewMinter(
		settings.TokenTTL, crypto, signer, providers, settings.DefaultTokenProvider, &clock)
	tokenValidator = token.NewValidator(crypto, verifier, providers, &clock)

	oauth = provider.NewOAuth(settings.ServiceAccount, settings.OAuth, nil, oauthRedirect)

	u2fstore := provider.NewFilesystemU2FStore(settings.U2F.StorePath)

	u2f = provider.NewU2F(
		settings.U2F.AppID, settings.U2F.TrustedFacets,
		u2fstore, createToken, u2fRedirect)
}

func errorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}
		err := c.Errors[0].Err
		c.HTML(c.Writer.Status(), "error.tmpl", gin.H{
			"error":        err.Error(),
			"unauthorized": c.Writer.Status() == http.StatusUnauthorized,
			"forbidden":    c.Writer.Status() == http.StatusForbidden,
		})
	}
}

func newGin(withStatic bool) (*gin.Engine) {
	r := gin.New()
	r.Use(GinLogger(syslog, true))
	r.Use(GinLogger(log.StandardLogger(), false))
	r.Use(gin.Recovery())
	r.Use(errorHandler())
	if withStatic {
		r.Static("/css", filepath.Join(*static, "css"))
		r.Static("/img", filepath.Join(*static, "img"))
		r.Static("/js", filepath.Join(*static, "js"))
	}
	// Must load html templates, gin will crash if no HTML renderer
	// exists.
	r.LoadHTMLGlob(filepath.Join(*templates, "*.tmpl"))
	return r
}

func main() {
	flag.Parse()

	syslog = log.New()
	syslog.Out = ioutil.Discard
	hook, err := logrus_syslog.NewSyslogHook("", "", syslogpkg.LOG_INFO, "")
	if err == nil {
		syslog.Hooks.Add(hook)
	}

	switch *syslogStyle {
	case "plain":
		syslog.Formatter = &log.TextFormatter{
			TimestampFormat: time.RFC3339,
			DisableColors: true}
	case "json":
		syslog.Formatter = &log.JSONFormatter{
			TimestampFormat: time.RFC3339}
	}

	if (*verbose) {
		log.SetLevel(log.DebugLevel)
	}

	setup()

	settings.U2FURL = "/login/u2f?state=%s"
	settings.FallbackURL = "/login/success"

	login := newGin(true)
	login.GET("/login/start", context.Wrap(loginHandler))
	login.GET("/login/success", context.Wrap(successHandler))
	login.GET("/logout", context.Wrap(logoutHandler))
	login.GET("/login/oauth2/callback", context.Wrap(session.Wrap(oauth.CallbackHandler)))
	login.GET("/login/u2f", context.Wrap(session.Wrap(u2f.Handler)))
	login.GET("/login/u2f/sign/request", context.Wrap(session.Wrap(u2f.SignRequestHandler)))
	login.POST("/login/u2f/sign/response", context.Wrap(session.Wrap(u2f.SignResponseHandler)))
	login.GET("/login/u2f/register/request", context.Wrap(session.Wrap(u2f.RegisterRequestHandler)))
	login.POST("/login/u2f/register/response", context.Wrap(session.Wrap(u2f.RegisterResponseHandler)))
	go login.Run("[::1]:9091")

	list := newGin(true)
	list.GET("/", context.Wrap(indexHandler))
	go list.Run("[::1]:9092")

	auth := newGin(false)
	auth.GET("/auth", context.Wrap(authHandler))
	auth.Run("[::1]:9090")
}
