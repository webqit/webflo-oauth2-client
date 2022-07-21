
/**
 * @imports
 */
import { _from as _arrFrom } from '@webqit/util/arr/index.js';
import Machine from "./Machine.js";
import Provider from './Provider.js';

/**
 * Client Object
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
     * Dynamically creates the URL for obtaining "authorization_code".
     * 
     * @param String    state 
     * @param String    provider 
     * @param Array     scope 
     * @param String    audience 
     * 
     * @returns String
     */
    createSignInUrl( { state, provider, scope = [], audience = null } = {} ) {
        const providr = this.provider( provider );
        scope = _arrFrom( scope );
        const url = providr.endpoints.signIn
            + '?response_type=code'
            + '&client_id=' + providr.clientId
            + '&redirect_uri=' + this.callbacks.signedIn
            + ( scope.length ? '&scope=' + scope.join( '%20' ) : '' ) // "openid" to include id_token, "offline_access" - to include refresh_token
            + ( audience ? '&audience=' + audience : '' )
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
    createSignOutUrl( { provider } = {} ) {
        const providr = this.provider( provider );
        if ( !providr.endpoints.signOut ) return this.callbacks.signedOut;
        const url = providr.endpoints.signOut
            + '?client_id=' + providr.clientId
            + '&returnTo=' + this.callbacks.signedOut;
        return url;
    }

    /**
     * Calls provider to exchange a code for token.
     * 
     * @param String    provider 
     * @param String    code 
     * 
     * @returns Object
     */
    async signInWithAuthorizationCode( { provider, code } = {} ) {
        const providr = this.provider( provider );
        const response = await providr.grant( 'authorization_code', code, {
            redirect_uri: this.callbacks.signedIn,
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
        return oauth;
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