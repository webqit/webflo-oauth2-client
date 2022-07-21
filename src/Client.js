
/**
 * @imports
 */
import { scopeSplit } from './util.js';
import Machine from "./Machine.js";
import Provider from './Provider.js';

/**
 * Client Class
 */
export default class Client extends Machine {

    /**
     * Initializes a Client instance
     * 
     * @param String    baseUrl - The base URL of the app, from which "callback URLs" are resolved
     * @param String    signedIn - The "callback URL" for when a user has been signed in at provider screen
     * @param String    signedOut - The "callback URL" for when a user has been signed out at provider screen
     * @param Object    rest - (Optional) Other URLs on the app which may function as "callback URLs"
     * @param String    privateKey - (Optional, but required where jwtSign() is called) The private for signing a JWT to an external service
     * @param Object    jwtokensRest - (Optional) Other attributes for signing a JWT to an external service
     * @param Object    providers - A hash of oauth2 providers. (See Provider constructor for details.)
     * @param Function  fetch - The function for making external requests.
     */
    constructor( {
        baseUrl,
        callbacks: {
            signedIn,
            signedOut,
            ...rest
        },
        jwtokens: {
            privateKey,
            ...jwtokensRest
        } = {}
    }, providers, fetch ) {
        super( { baseUrl, fetch } );
        // ---------
        Object.defineProperty( this, 'callbacks', { value: {}, enumerable: true } );
        const callbacks = { signedIn, signedOut, ...rest };
        Object.defineProperties( this.callbacks, Object.keys( callbacks ).reduce( ( prev, name ) => ( {
            [ name ]: { value: this.resolveUrl( callbacks[ name ] ), enumerable: true },
            ...prev,
        } ), {} ) );
        // ---------
        Object.defineProperty( this, 'jwtokens', { value: { privateKey, ...jwtokensRest }, enumerable: true } );
        // ---------
        this.providersConfig = providers;
        this.defaultProvider = Object.keys( providers )[ 0 ];
        this.providers = new Map;
    }

    /**
     * Returns a Provider instance.
     * 
     * @param String    name 
     * 
     * @returns String
     */
    provider( name = this.defaultProvider ) {
        if ( !this.providers.has( name ) ) {
            if ( !this.providersConfig[ name ] ) throw new Error( `The implied provider "${ name }" is not configured!` );
            this.providers.set( name, new Provider( name, this.providersConfig[ name ], this.fetch ) );
        }
        return this.providers.get( name );
    }

    /**
     * Calls provider to authenticate self - specifying an audience.
     * 
     * @param String    provider 
     * @param String    audience 
     * 
     * @returns Object
     */
    async signInWithClientCredentials( { provider, audience } = {} ) {
        const providr = this.provider( provider );
        const oauth =  await providr.grant( 'client_credentials', audience );
        return oauth;
    }

    /**
     * Calls provider to exchange a code for token.
     * 
     * @param String    provider
     * @param String    code
     * @param String    pkceVerifier
     * 
     * @returns Object
     */
    async signInWithAuthorizationCode( { provider, code, pkceVerifier = null } = {} ) {
        const providr = this.provider( provider );
        const response = await providr.grant( 'authorization_code', code, {
            redirect_uri: this.callbacks.signedIn,
            ...( pkceVerifier ? { code_verifier : pkceVerifier } : { }),
        } );
        const oauth = { ...response, provider: providr.name };
        if ( oauth.id_token ) {
            let id_token = oauth.id_token;
            delete oauth.id_token;
            try {
                id_token = await providr.jwtVerify( id_token );
            } catch ( e ) {
                throw e;
                id_token = await providr.jwtDecode( id_token );
            }
            oauth.header = id_token.header;
            oauth.signature = id_token.signature;
            oauth.info = id_token.payload;
        } else {
            oauth.info = {};
        }
        if ( oauth.refresh_token ) {
            // TODO: Store refresh_token and monitore access_token expiration so as to auto-refresh it
        }
        return oauth;
    }

    /**
     * Dynamically creates the URL for obtaining "authorization_code".
     * 
     * @param String    state 
     * @param String    provider 
     * @param Array     scope 
     * @param String    audience 
     * @param Boolean   offline 
     * @param String    pkceChallenge 
     * 
     * @returns String
     */
    generateAuthorizationSignInUrl( { state, provider, scope = [], audience = null, offline = false, pkceChallenge = null } = {} ) {
        const providr = this.provider( provider );
        const givenScopes = scopeSplit( scope );
        const incrementalAuth = givenScopes[ 0 ] === '+' ? givenScopes.shift() : false;
        const url = providr.endpoints.signIn
            + '?response_type=code'
            + '&client_id=' + providr.clientId
            + '&redirect_uri=' + this.callbacks.signedIn
            + ( givenScopes.length ? '&scope=' + givenScopes.join( '%20' ) : '' ) // "openid" to include id_token, "offline_access" - to include refresh_token
            + ( audience ? '&audience=' + audience : '' )
            + ( offline ? '&access_type=offline' : '' )
            + ( pkceChallenge ? '&code_challenge=' + pkceChallenge + '&code_challenge_method=S256' : '' )
            + ( incrementalAuth ? '&include_granted_scopes=true' : '' )
            + ( state ? '&state=' + state : '' );
        return url;
    }

    /**
     * Dynamically creates the URL for obtaining "authorization_code".
     * 
     * @param String    provider 
     * 
     * @returns String
     */
    generateAuthorizationSignOutUrl( { provider } = {} ) {
        const providr = this.provider( provider );
        if ( !providr.endpoints.signOut ) return this.callbacks.signedOut;
        const url = providr.endpoints.signOut
            + '?client_id=' + providr.clientId
            + '&returnTo=' + this.callbacks.signedOut;
        return url;
    }

    /**
     * Encodes data as a signed JWT.
     *
     * @param String|Object             data
     * @param Object                    params
     * 
     * @return String
     */
    jwtSign( data, params = {} ) {
        return new Promise(( resolve, reject ) => {
            this.jwt.sign( data, this.jwtokens.privateKey, {
                // Add issuer claims - usually this.baseUrl (Note: ending as a path: "url/", to be consistent with the same field in RemoteProvider.jwtVerify())
                issuer: this.baseUrl,
                // The default signing algorithm
                algorithm: 'RS256',
                // Add audience, etc claims
                ...params
            }, ( error, decoded ) => error ? reject( error ) : resolve( decoded ) );
        } );
    }

}