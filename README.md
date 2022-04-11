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
        baseUrl: process.env.OAUTH2_SERVER_BASE_URL, //e.g: https://example.us.auth0.com
        signIn: process.env.OAUTH2_SERVER_SIGN_IN_URL, //e.g: /authorize
        token: process.env.OAUTH2_SERVER_TOKEN_URL, //e.g: /oauth/token
        signOut: process.env.OAUTH2_SERVER_SIGN_OUT_URL, //e.g: /v2/logout
    },
    callbacks: {
        baseUrl: process.env.OAUTH2_APP_BASE_URL, //e.g: http://localhost:3000
        signedIn: process.env.OAUTH2_APP_SIGNED_IN_URL, //e.g: /signed-in
        signedOut: process.env.OAUTH2_APP_SIGNED_OUT_URL, //e.g: /signed-out
    },
    // Optional params and their defaults
    cookieValidity: 60 * 60 * 24 * 30,
    cookieName: '$webflo_oauth',
});
```

```js
export default function(event, app, next) {
    return oauth2Client(event).signIn(next)
};
```

```js
export default function(event, app, next) {
    if (oauth2Client(event).isSignedIn()) {
        return oauth2Client(event).signOut();
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
