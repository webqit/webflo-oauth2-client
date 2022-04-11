# Webflo OAuth2 Client

<!-- BADGES/ -->

<span class="badge-npmversion"><a href="https://npmjs.org/package/@webqit/webflo-oauth2-client" title="View this project on NPM"><img src="https://img.shields.io/npm/v/@webqit/webflo-oauth2-client.svg" alt="NPM version" /></a></span>
<span class="badge-npmdownloads"><a href="https://npmjs.org/package/@webqit/webflo-oauth2-client" title="View this project on NPM"><img src="https://img.shields.io/npm/dm/@webqit/webflo-oauth2-client.svg" alt="NPM downloads" /></a></span>

<!-- /BADGES -->


Isomorphic OAuth2 Authorization Code Flow library for Webflo.

```shell
npm i @webqit/webflo-oauth2-client
```

```js
import WebfloOAuth2Client from '@webqit/webflo-oauth2-client';
```

```js
const oauth2Client = navigationEvent => new WebfloOAuth2Client(navigationEvent, {
    // Required params
    clientId: process.env.OAUTH2_CLIENT_ID,
    clientSecret: process.env.OAUTH2_CLIENT_SECRET,
    endpoints: {
        baseUrl: process.env.OAUTH2_ENDPOINT_HOST, //e.g: https://example.us.auth0.com
        signIn: process.env.OAUTH2_SIGNIN_ENDPOINT, //e.g: /authorize
        token: process.env.OAUTH2_TOKEN_ENDPOINT, //e.g: /oauth/token
        signOut: process.env.OAUTH2_SIGNOUT_ENDPOINT, //e.g: /v2/logout
    },
    callbacks: {
        baseUrl: process.env.OAUTH2_CALLBACK_HOST, //e.g: http://localhost:3000
        signedIn: process.env.OAUTH2_SIGNIN_CALLBACK, //e.g: /signed-in
        signedOut: process.env.OAUTH2_SIGNOUT_CALLBACK, //e.g: /signed-out
    },
    // Optional params and their defaults
    cookieValidity: 60 * 60 * 24 * 30,
    cookieName: '$webflo_oauth',
});
```

Perform "signing" at any route; protect sub (next) routes:

```js
export default function(event, app, next) {
    let auth2 = oauth2Client(event);
    return auth2.signIn(next);
};
```

Perform "token exchange" at the process.env.OAUTH2_SIGNIN_CALLBACK route:

```js
export default function(event, app, next) {
    let auth2 = oauth2Client(event);
    if (auth2.isSigningIn()) {
        return auth2.handleToken();
    }
    return next();
};
```

Perform "signout" at any route:

```js
export default function(event, app, next) {
    let auth2 = oauth2Client(event);
    if (auth2.isSignedIn()) {
        return auth2.signOut();
    }
    return next();
};
```

## Documentation

Coming soon.

## Issues

To report bugs or request features, please submit an issue to this repository.

## License

MIT.
