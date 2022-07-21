# Webflo OAuth2 Client

<!-- BADGES/ -->

<span class="badge-npmversion"><a href="https://npmjs.org/package/@webqit/webflo-oauth2-client" title="View this project on NPM"><img src="https://img.shields.io/npm/v/@webqit/webflo-oauth2-client.svg" alt="NPM version" /></a></span>
<span class="badge-npmdownloads"><a href="https://npmjs.org/package/@webqit/webflo-oauth2-client" title="View this project on NPM"><img src="https://img.shields.io/npm/dm/@webqit/webflo-oauth2-client.svg" alt="NPM downloads" /></a></span>

<!-- /BADGES -->

Webflo OAuth2 library for Node.js.

## Installation

```shell
npm i @webqit/webflo-oauth2-client
```

## Usage

```js
import { Auth as WebfloOAuth2Client } from '@webqit/webflo-oauth2-client';
```

### Initialization

```js
const oauth2Client = ( httpEvent, fetch ) => {

    // Client app config
    const client = {
        // The application's base URL. E.g. http://localhost:3000/ (local), https://example.com/ (production)
        baseUrl: process.env.OAUTH2_CALLBACK_HOST,
        // Application's auth-flow endpoints, relative to base URL
        callbacks: {
            // The route where you'll handle signed-in callback from provider screen. (See below: The "Signed-In" Callback Route)
            signedIn: '/auth',
            // The route where you'll handle signed-out callback from provider screen. (See below: A "Sign Out" Route)
            signedOut: '/',
        },
    };

    // Provider: auth0
    const auth0 = {
        // Auth0-issued client ID
        clientId: process.env.AUTH0_CLIENT_ID,
        // Auth0-issued client secret
        clientSecret: process.env.AUTH0_CLIENT_SECRET,
        // OAuth2 server base URL. E.g. https://example.us.auth0.com/
        baseUrl: process.env.AUTH0_BASE_URL,
        // Auth0-issued auth-flow endpoints, relative to base URL
        endpoints: {
            signIn: '/authorize',
            token: '/oauth/token',
            revoke: undefined,
            signOut: '/v2/logout',
        },
        // Parameters for verifying Auth0-issued ID Tokens
        jwtokens: { jwksUrl: '.well-known/jwks.json', }
    };

    // Provider: google
    const google = {
        // Google-issued client ID
        clientId: process.env.GOOGLE_CLIENT_ID,
        // Google-issued client secret
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        // OAuth2 server base URL. Always https://oauth2.googleapis.com/ for Google
        baseUrl: process.env.GOOGLE_BASE_URL,
        // Google-issued auth-flow endpoints, relative to base URL
        endpoints: {
            signIn: 'https://accounts.google.com/o/oauth2/v2/auth',
            token: '/token',
            revoke: '/revoke',
            signOut: undefined,
        },
        // Parameters for verifying Google-issued ID Tokens
        jwtokens: { jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', }
    };

    // Auth instance
    return new WebfloOAuth2Client( httpEvent, {
        client, providers: { google/* as default provider */, auth0 },
    }, fetch );

};
```

### Initialization Route

At the application's root handler, you'd initialize oauth2 client into the `context` object that is passed around:

```js
export default function( httpEvent, context, next, fetch ) {
    context.oauth2 = oauth2Client( httpEvent, fetch );
    if ( next.pathname ) return next( context );
    return { titleBar: 'Home' };
}
```

### A Protected "Sign In" Route

To protect a route, you'd call the `signIn()` method with optional fields - `{ provider /* defaults to the name of the first provider in list */, scope, audience }`:

```js
export default function( httpEvent, context, next, fetch ) {
    return context.oauth2.signIn( { /* optional */scope: 'openid' }, session => {
        // Authenticated...
        // otherwise this function is not called, and user is redirected to provider sign in screen
        // session is same as context.oauth2.session

        // Are we going to a protected child page?
        // session can always be accessed as context.oauth2.session down the hierarchy
        if ( next.pathname ) return next( context );

        // See what's in auth session
        console.log( session ); // { access_token, token_type: 'Bearer', scope, provider, info, ...etc }
        // See what's in session.info
        console.log( session.info ); // { iss, sub: <user ID>, exp, ...etc }
        // (If "profile", "email" were in the value of the "scope" parameter (as an array or a space-delimitted string), other infos would be available: email, name, avatar_url, etc.)

        // Call an API endpoint at provider
        const provider = context.oauth2.client.provider( /* specify provider name, otherwise default provider is implied */ );
        const endpoint = '/userinfo'; // Or if defined in provider settings object above: endpoint = provider.endpoints.userinfo
        const user = await provider.call( session.access_token, endpoint, { ...optionalBody } );

        /*
        Or if you wish...
        const user = await fetch( 'https://oauth2.example.com/endpoint', {
            body: JSON.stringify( { ...optionalBody } ),
            headers: { 'Content-Type': 'application/json', Authorization: session.access_token }
        } ).then( res => res.json() );
        */

        // Show accounts page
        return {
            titleBar: 'My Account',
            email: user.email,
        }
    } );
}
```

<details>
<summary>The <code>context.oauth2.signIn()</code> function could also be called without a callback...</summary>

```js
export default function( httpEvent, context, next, fetch ) {
    let session, redirect, sessionOrRedirect = context.oauth2.signIn( { /* optional */scope: 'openid' } );
    if ( sessionOrRedirect instanceof httpEvent.Response ) {
        // User is being redirected to provider sign in screen
        return ( redirect = sessionOrRedirect /* formality assignment */ );
    }
    // Authenticated...
    session = sessionOrRedirect;
    // session is same as context.oauth2.session
    
    // Are we going to a protected child page?
    // session can always be accessed as context.oauth2.session down the hierarchy
    if ( next.pathname ) return next( context );

    // See what's in auth session
    console.log( session ); // { access_token, token_type: 'Bearer', scope, provider, info, ...etc }
    // See what's in session.info
    console.log( session.info ); // { iss, sub: <user ID>, exp, ...etc }
    // (If "profile", "email" were in the value of the "scope" parameter (as an array or a space-delimitted string), other infos would be available: email, name, avatar_url, etc.)

    // Call an API endpoint at provider
    const provider = context.oauth2.client.provider( /* specify provider name, otherwise default provider is implied */ );
    const endpoint = '/userinfo'; // Or if defined in provider settings object above: endpoint = provider.endpoints.userinfo
    const user = await provider.call( session.access_token, endpoint, { ...optionalBody } );

    /*
    Or if you wish...
    const user = await fetch( 'https://oauth2.example.com/endpoint', {
        body: JSON.stringify( { ...optionalBody } ),
        headers: { 'Content-Type': 'application/json', Authorization: session.access_token }
    } ).then( res => res.json() );
    */

    // Show accounts page
    return {
        titleBar: 'My Account',
        email: user.email,
    }
}
```

</details>


### The "Signed In" Callback Route

To handle the "signed-in" redirect from *provider* screen - at the specified callback URL `client.callbacks.signedIn`:

```js
export default function( httpEvent, context, next ) {
    if ( context.oauth2.isSigningIn() /* Detects if a sign-in session is ongoing */ ) {
        // Performs "authorization_code" grant and redirects user back to the original protected route - where signIn() was called
        return context.oauth2.handleSignInCallback();
    }
    // Returns the context.oauth2.session object or false
    return context.oauth2.isSignedIn()?.info || {};
}
```

### A "Sign Out" Route

To perform "sign out" at any route:

```js
export default function( httpEvent, context, next ) {
    if ( context.oauth2.isSignedIn() ) {
        // User is signed-out (and is redirected to provider's sign-out URL, where given),
        // then redirected back to "/" as specified in client.callbacks.signedOut
        return context.oauth2.signOut();
    }
    return next();
}
```

## Full Documentation

Fullm documentation, including integrating other providers, coming soon.

## Issues

To report bugs or request features, please submit an issue to this repository.

## License

MIT.
