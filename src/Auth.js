
/**
 * @imports
 */
import { _intersect, _from as _arrFrom } from '@webqit/util/arr/index.js';
import { _isString } from '@webqit/util/js/index.js';
import Client from './Client.js';

/**
 * Auth Object
 */
export default class Auth {

    /**
     * Initializes an Auth instance.
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
     * 
     * @return object
     */
    isSignedIn( { provider, scope = [], audience = null } = {} ) {
        if ( !this.session.access_token ) return false;
        const givenScopeds = _arrFrom( scope );
        if ( provider && this.session.provider !== provider ) return false;
        if ( givenScopeds.length ) {
            let activeScope = ( this.session.scope || '' ).split( ' ' ).map( s => s.split( '.' ).pop()/* some google scopes come back as URLs ending with the scope extension */.trim() );
            if ( _intersect( givenScopeds, activeScope).length !== givenScopeds.length ) return false;
        }
        if ( audience ) {
            let activeAud = this.session.identity.aud.split( ' ' ).map( s => s.trim() );
            if ( _intersect( _arrFrom( audience ), activeAud ).length !== activeAud.length ) return false;
        }
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
     * @param Function      next
     * 
     * @return Object|Promise|Response
     */
    signIn( { provider, scope = [], audience = null } = {}, next = null ) {
        // Already authenticated?
        let session;
        if ( session = this.isSignedIn( { provider, scope, audience } ) ) return next ? next( session ) : session;
        // Initiate Authentication Code Flow
        return this.createSignInRedirect( { provider, scope, audience } );
    }
    
    /**
     * Initiates the OAuth2 Authentication Code Flow
     * by sending the client to the specified IdP.
     * 
     * (Be sure to end current running code after calling this function.)
     * 
     * @param String        provider
     * @param Array         scope - Optional "scope" parameter for the request.
     * @param String        audience - Optional "audience" parameter for the request.
     * 
     * @return void
     */
    createSignInRedirect( { provider, scope = [], audience = null } = {} ) {
        // Is code auth
        let i = 0, ref = '';
        while( i < 1 ) { ref += Math.random(); i ++; }
        this.session.redirectState = { ref, provider, url: this.httpEvent.url.href };
        let rdr = this.client.createSignInUrl( { state: ref, provider, scope, audience } );
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
            const newSession = await this.client.signInWithAuthorizationCode( { provider: redirectState.provider, code: url.query.code } );
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
        const rdr = this.client.createSignOutUrl( { provider } );
        return new this.httpEvent.Response( null, { status: 302, headers: { Location: rdr } } );
    }

}