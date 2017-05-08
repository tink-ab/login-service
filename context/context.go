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
package context

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Context interface {
	SetCookie(h *http.Cookie)
	SetHeader(name string, value string)
	AddHeader(name string, value string)

	Error(code int, err error)

	UserIP() string
	Authorization() string
	Groups() string

	Redirect(url string)

	Query(key string) string
	Cookies() []*http.Cookie

	BindJSON(obj interface{}) error

	String(text string)
	JSON(obj interface{})
	HTML(template string, data H)

	SessionID() string
	ClientMark() string
}

type H map[string]interface{}

func newMark() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

type GinContext struct {
	g *gin.Context
}

func (c *GinContext) Query(key string) string {
	return c.g.Query(key)
}

func (c *GinContext) UserIP() string {
	return c.g.Request.Header.Get("x-real-ip")
}

func (c *GinContext) Authorization() string {
	return c.g.Request.Header.Get("Authorization")
}

func (c *GinContext) Groups() string {
	return c.g.Request.Header.Get("x-group")
}

func (c *GinContext) Cookies() []*http.Cookie {
	return c.g.Request.Cookies()
}

func (c *GinContext) SetCookie(h *http.Cookie) {
	http.SetCookie(c.g.Writer, h)
}

func (c *GinContext) SetHeader(name string, value string) {
	c.g.Writer.Header().Set(name, value)
}

func (c *GinContext) AddHeader(name string, value string) {
	c.g.Writer.Header().Add(name, value)
}

func (c *GinContext) Error(code int, err error) {
	c.g.AbortWithError(code, err)
}

func (c *GinContext) HTML(template string, data H) {
	c.g.HTML(http.StatusOK, template, data)
}

func (c *GinContext) JSON(obj interface{}) {
	c.g.JSON(http.StatusOK, obj)
}

func (c *GinContext) Redirect(url string) {
	c.g.Redirect(http.StatusFound, url)
}

func (c *GinContext) String(text string) {
	c.g.String(http.StatusOK, text)
}

func (c *GinContext) SessionID() string {
	return c.g.Query("state")
}

// The Client Mark is used as a second-factor to the SessionID. SessionID
// is sent in the authentication URLs to allow for multiple concurrent sessions
// (i.e. multiple tabs being restored or something similar). A client should
// always have one, so if no one is presented one should be generated.
// Validation of the client mark is done by session.Wrap.
func (c *GinContext) ClientMark() string {
	hc, err := c.g.Request.Cookie("client-id")
	if err != nil {
		hc = &http.Cookie{
			Name:     "client-id",
			Path:     "/login/",
			Value:    newMark(),
			Secure:   true,
			HttpOnly: true}
		http.SetCookie(c.g.Writer, hc)
	}
	return hc.Value
}

func (c *GinContext) BindJSON(obj interface{}) error {
	return c.g.BindJSON(obj)
}

func NewGin(g *gin.Context) *GinContext {
	c := GinContext{g: g}
	return &c
}

func Wrap(rh func(Context)) func(*gin.Context) {
	return func(c *gin.Context) {
		rh(NewGin(c))
	}
}
