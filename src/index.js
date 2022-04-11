
/**
 * @imports
 */
import Jsonwebtoken from 'jsonwebtoken';
import _intersect from '@webqit/util/arr/intersect.js';
import _arrFrom from '@webqit/util/arr/from.js';
import _promise from '@webqit/util/js/promise.js';

/**
 * OAuth util class
 */
export default class WebfloOAuth2Client {

    /**
     * Creates an auth API
     * 
     * @param object navigationEvent
     * @param object params 
     *      clientId,
     *      clientSecret,
     *      endpoints,
     *          baseUrl,
     *          signIn,
     *          token,
     *          signOut,
     *      callbacks
     *          baseUrl,
     *          signedIn,
     *          signedOut
     * '
     * @return void
     */
    constructor(navigationEvent, params) {
        this.navigationEvent = navigationEvent;
        this.session = navigationEvent.sessionFactory(params.cookieName || '$webflo_oauth', {duration: params.cookieValidity || 60 * 60 * 24 * 30}).get();
        this.params = params;
        this.endpoints = {
            signInUrl: params.endpoints.baseUrl + params.endpoints.signIn,
            tokenUrl: params.endpoints.baseUrl + params.endpoints.token,
            signOutUrl: params.endpoints.baseUrl + params.endpoints.signOut,
        };
        this.callbacks = {
            signedInUrl: params.callbacks.baseUrl + params.callbacks.signedIn,
            signedOutUrl: params.callbacks.baseUrl + params.callbacks.signedOut,
        };
    }
    
    /**
     * Checks if the current session is authenticated,
     * and otpionally, with the specified scopes.
     * Initiates the Authentication Code Flow if not.
     * 
     * (Be sure to end current running code after calling this function.)
     * 
     * @param function next.
     * @param array scopes - Optional "scopes" to require.
     * @param string audience - Optional "audience" to require.
     * 
     * @return void
     */
    signIn(next, scopes = [], audience = null) {
        // Already authenticated?
        let oauth;
        if (oauth = this.isSignedIn(scopes, audience)) {
            return next(oauth);
        }
        // Initiate Authentication Code Flow
        return this.requestToken(scopes, audience);
    }
    
    /**
     * Checks if the current session is authenticated,
     * and otpionally, with the specified scopes.
     * 
     * @param array scopes - Optional "scopes" to check.
     * @param string audience - Optional "audience" to check.
     * 
     * @return object
     */
    isSignedIn(scopes = [], audience = null) {
        if (!this.session.oauth) {
            return false;
        }
        let givenScopeds = _arrFrom(scopes);
        if (givenScopeds.length) {
            let activeScope = (this.session.oauth.scope || '').split(' ').map(s => s.trim());
            if (_intersect(givenScopeds, activeScope).length !== givenScopeds.length) {
                return false;
            }
        }
        if (audience) {
            let activeAud = this.session.oauth.identity.aud.split(' ').map(s => s.trim());
            if (_intersect(_arrFrom(audience), activeAud).length !== activeAud.length) {
                return false;
            }
        }
        return this.session.oauth;
    }
    
    /**
     * Initiates the OAuth2 Authentication Code Flow
     * by sending the client to the specified IdP.
     * 
     * (Be sure to end current running code after calling this function.)
     * 
     * @param array scopes - Optional "scopes" parameter for the request.
     * @param string audience - Optional "audience" parameter for the request.
     * 
     * @return void
     */
    requestToken(scopes = [], audience = null) {
        // Is code auth
        let i = 0, oauthStateCode = '';
        while(i < 1) {oauthStateCode += Math.random(); i ++;}
        this.session.oauthStateCode = oauthStateCode;
        this.session.oauthStateUrl = this.navigationEvent.url.href;
        let rdr = this.endpoints.signInUrl
            + '?response_type=code'
            + '&client_id=' + this.params.clientId
            + '&redirect_uri=' + this.callbacks.signedInUrl
            + (scopes.length ? '&scope=' + _arrFrom(scopes).join('%20') : '') // "openid" to include id_token, "offline_access" - to include refresh_token
            + (audience ? '&audience=' + audience : '')
            + (oauthStateCode ? '&state=' + oauthStateCode : '');
        return new this.navigationEvent.Response(null, {status: 302, headers: {location: rdr}});
    }
    
    /**
     * Checks if the current session is being authenticated,
     * but pending token handling.
     * 
     * @return object
     */
    isSigningIn() {
        return this.session.oauthStateCode 
        && this.session.oauthStateCode
        && this.navigationEvent.url.query.code;
    }

    /**
     * Handles the redirection from the OAuth2 Authentication Code Flow;
     * expects to see the "code" and "state" parameter in the URL.
     * 
     * Exchanges the recieved "code" for tokens and stores the result
     * as "oauth" in the user session.
     * 
     * On success, redirects the client back to the URL that initiated the
     * Authentication Code Flow.
     * 
     * @param function callback
     * 
     * @return Promise
     */
    async handleToken(callback = null) {
        let url = this.navigationEvent.url;
        let oauthStateCode = this.session.oauthStateCode;
        let oauthStateUrl = this.session.oauthStateUrl;
        if (!oauthStateCode || !url.query.code/* token code */) {
            return;
        }
        delete this.session.oauthStateCode;
        delete this.session.oauthStateUrl;
        if (url.query.state !== oauthStateCode) {
            return new this.navigationEvent.Response(null, {status: 401, statusText: 'Unauthorized - Invalid request; state mismatch.'});
        }

        let response;
        try {
            response = await this.navigationEvent.globals.fetch(this.endpoints.tokenUrl, {
                method: 'POST',
                body: JSON.stringify({
                    grant_type: 'authorization_code',           // or refresh_token
                    client_id: this.params.clientId,
                    client_secret: this.params.clientSecret,    // not needed for type refresh_token
                    code: url.query.code,                       // not needed for type refresh_token
                    redirect_uri: this.callbacks.signedInUrl,   // not needed for type refresh_token
                                                                // refresh_token: the body.refresh_token in previous request
                }),
                headers: {'Content-Type': 'application/json'},
            }).then(res => res.ok ? res.json() : Promise.reject(res.statusText));
        } catch(e) {
            return new this.navigationEvent.Response(null, {status: 401, statusText: 'Unauthorized - Internal network error - ' + e + '.'});
        }

        this.session.oauth = { ...response };
        if (response.id_token) {
            response.id_token = Jsonwebtoken.decode(response.id_token, {complete: true});
            // Verify signing algorithm - "data.id_token.header.alg" - HS256, RS256
            // Verify token audience claims - "data.id_token.payload.aud" - roughly this.params.clientId
            // Verify permissions (scopes) - "data.id_token.payload.scopes" - from the initiator request
            // Verify issuer claims - "data.id_token.payload.iss" - usually the domain part in this.endpoints.signInUrl
            // Verify expiration - "data.id_token.payload.exp" - must be after the current date/time
            // Starts a signIn session
            delete this.session.oauth.id_token;
        }
        if (callback) {
            this.session.oauth.identity = await callback(response);
        } else {
            this.session.oauth.identity = (response.id_token || {}).payload;
        }
        // Redirect back to initiator URL
        return new this.navigationEvent.Response(null, {status: 302, headers: {location: oauthStateUrl}});

    }
            
    /**
     * Terminates the current signIn session.
     * 
     * @param Bool      fromSource
     * 
     * @return void
     */
    signOut(fromSource = true) {
        delete this.session.oauth;
        if (!fromSource || !this.endpoints.signOutUrl) return;
        let rdr = this.endpoints.signOutUrl
        + '?client_id=' + this.params.clientId
        + '&returnTo=' + this.callbacks.signedOutUrl;
        return new this.navigationEvent.Response(null, {status: 302, headers: {location: rdr}});
    }
}