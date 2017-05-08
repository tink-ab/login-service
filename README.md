# login-service

Central authentication service

Status: Production

## What is this?

Tink's `login-service` is a reverse proxy made to authenticate users within the organization
in a secure manner. To authenticate the use of an U2F security device is required.
When authenticated, the user is provided with a token valid for a configurable amount of time
granting the user access to the backend service for that duration.

Central token revocation and multiple security domains are supported.

## How-to

Start by installing `login-service` and `nginx`. For `login-service` to start you need to
fill in a number of files in `/etc/login-service.yaml`. The configuration for nginx can
be found under `etc/nginx/`.

In order to use Google OAuth to authenticate your Google Apps domain you will need to set
up OAuth credentials. See https://developers.google.com/identity/protocols/OAuth2.

There are quite a few fields in the nginx configuration and in `login-service.yaml` that you
need to set. When finished try to access "x.test.com". You should be asked to sign in
(if you're not already signed in) to your Google account and then to register a new U2F key.
When registered you will be asked to authenticate the access to the specific security domain.

You can then logout (login.test.com/logout) and then access "x.test.com"
again to try the normal flow when the user is registered.
