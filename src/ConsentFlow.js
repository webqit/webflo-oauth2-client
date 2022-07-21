
/**
 * @imports
 */
import { _intersect, _from as _arrFrom } from '@webqit/util/arr/index.js';
import { _isString } from '@webqit/util/js/index.js';
import { scopeSplit, base64URLEncode } from './util.js';
import Client from './Client.js';
import crypto from 'crypto';

/**
 * ConsentFlow Class
 */
export default class ConsentFlow {

    /**
     * Initializes an ConsentFlow instance.
     * 
     * @param Object    httpEvent - The Webflo HttpEvent
     * @param Object    client - The client definition object. (See Client constructor for details.)
     * @param Object    providers - A hash of oauth2 providers. (See Provider constructor for details.)
     * @param String    cookieName - (Optional) The name to give session cookies.
     * @param Number    cookieValidity - (Optional) The validity to give session cookies.
     * @param Function  fetch - The function for making external requests.
     */
    constructor( httpEvent, {
        client,
        providers,
        cookieName = null,
        cookieValidity = null
    }, fetch ) {
        this.httpEvent = httpEvent;
        this.session = httpEvent.sessionFactory( cookieName || '$webflo_oauth', { duration: cookieValidity || 60 * 60 * 24 * 30 } ).get();
        this.client = new Client( client, providers, fetch );
    }
    
    /**
     * Checks if the current session is authenticated,
     * and otpionally, with the specified scope.
     * 
     * @param String        provider
     * @param Array         scope - Optional "scope" to check.
     * @param String        audience - Optional "audience" to check.
     * @param Boolean       offline - Optional "access_type" of "offline".
     * 
     * @return object
     */
    isSignedIn( { provider, scope = [], audience = null, offline = false } = {} ) {
        if ( !this.session.access_token ) return false;
        if ( provider && this.session.provider !== provider ) return false;
        const givenScopes = scopeSplit( scope );
        if ( givenScopes.length ) {
            const activeScopes = ( this.session.scope || '' ).split( ' ' ).map( s => s.trim() );
            const matched = givenScopes.reduce( ( prev, givenScope ) => {
                if ( !prev || [ 'offline_access', '+'/* include_granted_scopes */ ].includes( givenScope ) ) return prev;
                return activeScopes.some( activeScope => {
                    if ( activeScope === givenScope ) return true;
                    // Some google scopes come back as URLs ending with the scope extension
                    if ( activeScope.startsWith( 'https://' ) && activeScope.split( '.' ).pop() ===  givenScope ) return true;
                } );
            }, true );
            if ( !matched ) return false;
        }
        if ( audience ) {
            let activeAud = this.session.identity.aud.split( ' ' ).map( s => s.trim() );
            if ( _intersect( _arrFrom( audience ), activeAud ).length !== activeAud.length ) return false;
        }
        if ( ( offline || givenScopes.includes( 'offline_access' ) ) && !this.session.refresh_token ) return false;
        return this.session
    }
    
    /**
     * Checks if the current session is authenticated,
     * and otpionally, with the specified scope.
     * Initiates the Authentication Code Flow if not.
     * 
     * (Be sure to end current running code after calling this function.)
     * 
     * @param String        provider
     * @param Array         scope - Optional. Include, e.g. "openid" to get profile info
     * @param String        audience - Optional "audience" to require.
     * @param Boolean       offline - Optional "access_type" of "offline".
     * @param Boolean       pkce - Optional Authorization Code Flow with Proof Key for Code Exchange (PKCE).
     * @param Function      next
     * 
     * @return Object|Promise|Response
     */
    signIn( { provider, scope = [], audience = null, offline = false, pkce = false } = {}, next = null ) {
        // Already authenticated?
        let session;
        if ( session = this.isSignedIn( { provider, scope, audience, offline } ) ) return next ? next( session ) : session;
        // Initiate Authentication Code Flow
        return this.createSignInRedirect( { provider, scope, audience, offline, pkce } );
    }
    
    /**
     * Alias of signIn(), but with pkce set to true.
     * 
     * @param String        provider
     * @param Array         scope - Optional. Include, e.g. "openid" to get profile info
     * @param String        audience - Optional "audience" to require.
     * @param Boolean       offline - Optional "access_type" of "offline".
     * @param Function      next
     * 
     * @return Object|Promise|Response
     */
    signInWithProofKey( { provider, scope = [], audience = null, offline = false } = {}, next = null ) {
        return this.signIn( { provider, scope, audience, offline, pkce: true }, next );
    }
    
    /**
     * Initiates the OAuth2 Authentication Code Flow
     * by sending the client to the specified IdP.
     * 
     * (Be sure to end current running code after calling this function.)
     * 
     * @param String        provider
     * @param Array         scope - Optional "scope" parameter for the request.
     * @param String        audience - Optional: "audience" parameter for the request.
     * @param Boolean       offline - Optional: "access_type" of "offline".
     * @param Boolean       pkce - Optional: perform Authorization Code Flow with Proof Key for Code Exchange (PKCE).
     * 
     * @return void
     */
    createSignInRedirect( { provider, scope = [], audience = null, offline = false, pkce = false } = {} ) {
        // Is code auth
        let i = 0, ref = '', pkceVerifier, pkceChallenge;
        while( i < 1 ) { ref += Math.random(); i ++; }
        if ( pkce ) {
            pkceVerifier = base64URLEncode( crypto.randomBytes( 32 ) );
            pkceChallenge = base64URLEncode( crypto.createHash( 'sha256' ).update( pkceVerifier ).digest() );
        }
        this.session.redirectState = { ref, provider, url: this.httpEvent.url.href, pkceVerifier };
        let rdr = this.client.generateAuthorizationSignInUrl( { state: ref, provider, scope, audience, offline, pkceChallenge } );
        return new this.httpEvent.Response( null, { status: 302, headers: { Location: rdr } } );
    }
    
    /**
     * Checks if the current session is being authenticated,
     * but pending token handling.
     * 
     * @return object
     */
    isSigningIn() {
        return this.session.redirectState;
    }
    
    /**
     * Handles the redirection from the OAuth2 Authentication Code Flow;
     * expects to see the "code" and "state" parameter in the URL.
     * 
     * Exchanges the recieved "code" for tokens and stores the result
     * as "oauth" in the auth session.
     * 
     * On success, redirects the client back to the URL that initiated the
     * Authentication Code Flow.
     * 
     * @return Promise
     */
    async handleSignInCallback() {
        const url = this.httpEvent.url;
        const redirectState = this.session.redirectState;
        if ( !redirectState || !url.query.code/* token code */ ) return;
        if ( url.query.state !== redirectState.ref ) {
            return new this.httpEvent.Response( null, { status: 401, statusText: 'Unauthorized - Invalid request; state mismatch.' } );
        }
        try {
            delete this.session.redirectState;
            const newSession = await this.client.signInWithAuthorizationCode( { provider: redirectState.provider, code: url.query.code, pkceVerifier: redirectState.pkceVerifier } );
            Object.keys( newSession ).forEach( key => {
                this.session[ key ] = newSession[ key ];
            } );
        } catch( e ) {
            return new this.httpEvent.Response( null, { status: 401, statusText: 'Unauthorized - Internal network error - ' + e + '.' } );
        }
        // Redirect back to initiator URL
        return new this.httpEvent.Response( null, { status: 302, headers: { Location: redirectState.url } } );
    }
            
    /**
     * Terminates the current signIn session.
     * 
     * @return Response
     */
    signOut() {
        const { provider } = this.session;
        Object.keys( this.session ).forEach( key => {
            delete this.session[ key ];
        } );
        return this.createSignOutRedirect( { provider } );
    }
            
    /**
     * Terminates the current signIn session.
     * 
     * @param String        provider
     * 
     * @return Response
     */
    createSignOutRedirect( { provider } = {} ) {
        const rdr = this.client.generateAuthorizationSignOutUrl( { provider } );
        return new this.httpEvent.Response( null, { status: 302, headers: { Location: rdr } } );
    }

}