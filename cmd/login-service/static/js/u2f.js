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

function registered(resp) {
  var state = $('body').attr('state');
  $.post('/login/u2f/register/response?state=' + state,
      JSON.stringify(resp)).done(function() {
    // Reload stage to be redirected to next stage
    window.location.reload();
  }).fail(function() {
    console.log("U2F registration failed, please retry");
    window.location.reload();
  });
}

function register() {
  var state = $('body').attr('state');
  $.getJSON('/login/u2f/register/request?state=' + state).done(function(req) {
    // Chrome changed the default behaviour of u2f.register in Chrome 66.
    // attestation = direct is required to sign this request by the physical device
    // otherwise Chrome will issue a self-signed certificate to sign the request with.
    //
    // See more at https://www.chromium.org/security-keys
    req.attestation = "direct";

    u2f.register(req.appId, [req], [], registered, 60);
  });
}

function signed(resp) {
  console.log(resp);
  var state = $('body').attr('state');
  $.post('/login/u2f/sign/response?state=' + state, JSON.stringify(resp)).done(function(r) {
    // Reload stage to be redirected to next stage
    window.location.reload();
  }).fail(function() {
    console.log("U2F signing failed, please retry");
    window.location.reload();
  });

}

function sign() {
  var state = $('body').attr('state');
  $.getJSON('/login/u2f/sign/request?state=' + state).done(function(req) {
    console.log(req);
    var r = req.signRequests[0];
    u2f.sign(r.appId, r.challenge, req.signRequests, signed, 60);
  });
}
