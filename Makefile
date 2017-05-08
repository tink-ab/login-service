#
# Copyright 2017 Tink AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

login-service: $(wildcard cmd/login-service/*.go) $(wildcard **/*.go) $(wildcard *.go)
	go build -o $@ github.com/tink-ab/tink-login-service/cmd/$@

ecdsa-gen: $(wildcard cmd/ecdsa-gen/*.go)
	go build -o $@ github.com/tink-ab/tink-login-service/cmd/$@

install-share:
	mkdir -p $(DESTDIR)/usr/share/login-service
	cp -r cmd/login-service/static/. $(DESTDIR)/usr/share/login-service/static
	cp -r cmd/login-service/templates/. $(DESTDIR)/usr/share/login-service/templates

install: install-share
	mkdir -p $(DESTDIR)/usr/bin
	install -oroot -groot -m755 login-service $(DESTDIR)/usr/bin/

deb:
	gbp buildpackage --git-ignore-new --git-upstream-tree=master \
		--git-builder='debuild -i -I -us -uc'

.PHONY: install
