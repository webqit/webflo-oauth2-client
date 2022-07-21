
/**
 * @imports
 */
import JwksClient from 'jwks-rsa';
import Machine from "./Machine.js";

/**
 * Provider Class
 */
export default class Provider extends Machine {

    /**
     * Initializes a Provider instance
     * 
     * @param String    name - The name of the provider
     * @param String    clientId - The "clientId" from provider
     * @param String    clientSecret - The "clientSecret" from provider
     * @param String    baseUrl - The base URL of the provider oauth2 server, from which "endpoint URLs" are resolved
     * @param String    signIn - The "endpoint URL" for redirecting a user to sign in at provider screen
     * @param String    token - The "endpoint URL" for performing token grants with provider
     * @param String    revoke - (Optional) The "endpoint URL" for performing token revokation with provider
     * @param String    signOut - The "endpoint URL" for redirecting a user to sign out at provider screen
     * @param Object    rest - (Optional) Other URLs which may function as "endpoint URLs"
     * @param String    publicKey - (Mutually exclusive with jwksUrl) The public key for verifying a JWT from provider
     * @param String    jwksUrl - (Mutually exclusive with publicKey) The URL from which to fetch the jwks for verifying a JWT from provider
     * @param Object    jwtokensRest - (Optional) Other attributes for verifying a JWT from provider
     * @param Function  fetch - The function for making external requests.
     */
    constructor( name, {
        clientId,
        clientSecret,
        baseUrl,
        endpoints: {
            signIn,
            token,
            revoke,
            signOut,
            ...rest
        },
        jwtokens: {
            publicKey = null,
            jwksUrl = null,
            issuer = null,
            ...jwtokensRest
        } = {}
    }, fetch ) {
        super( { baseUrl, fetch } );
        // ---------
        Object.defineProperty( this, 'name', { value: name, enumerable: true } );
        Object.defineProperty( this, 'clientId', { value: clientId, enumerable: true } );
        Object.defineProperty( this, 'clientSecret', { value: clientSecret, enumerable: true } );
        Object.defineProperty( this, 'endpoints', { value: {}, enumerable: true } );
        const endpoints = { signIn, token, revoke, signOut, ...rest };
        Object.defineProperties( this.endpoints, Object.keys( endpoints ).reduce( ( prev, name ) => ( {
            [ name ]: { value: this.resolveUrl( endpoints[ name ] ), enumerable: true },
            ...prev,
        } ), {} ) );
        // ---------
        Object.defineProperty( this, 'jwtokens', { value: {
            publicKey, jwksUrl, issuer, ...jwtokensRest
        }, enumerable: true } );
        // ---------
    }

    /**
     * Calls for a token grant.
     *
     * @param String                grantType - "authorization_code"|"refresh_token"|"client_credentials"
     * @param String                tokenOrAudience
     * @param Object                options
     * 
     * @return Object
     */
    grant( grantType, tokenOrAudience, options = {} ) {
        if ( !this.endpoints.token ) throw new Error( 'No "token" endpoint defined.' );
        const params = { client_id: this.clientId, client_secret: this.clientSecret, grant_type: grantType, ...options, };
        // Properly set the token
        if ( grantType === 'refresh_token' ) { params.refresh_token = tokenOrAudience; }
        else if ( grantType === 'authorization_code' ) { params.code = tokenOrAudience; }
        else if ( grantType === 'client_credentials' ) { params.audience = tokenOrAudience; }
        else throw new Error( `Grant type "${ grantType }" unknown!` );
        // Go...
        return this.fetch( this.endpoints.token, {
            method: 'POST',
            body: JSON.stringify( params ),
            headers: { 'Content-Type': 'application/json', },
        } ).then( res => res.ok ? res.json() : Promise.reject( `${ res.status } - ${ res.statusText }` ) );
    }

    /**
     * Calls for a token to be revoked.
     *
     * @param String                token
     * 
     * @return Object
     */
    revoke( token ) {
        if ( !this.endpoints.revoke ) throw new Error( 'No "revoke" endpoint defined.' );
        return this.fetch( this.endpoints.revoke, {
            method: 'POST',
            body: JSON.stringify( { token } ),
            headers: { 'Content-Type': 'application/json', },
        } ).then( res => res.ok ? res.json() : Promise.reject( `${ res.status } - ${ res.statusText }` ) );
    }

    /**
     * Calls an endpoint.
     *
     * @param String                bearerToken
     * @param String                endpoint
     * @param Object                data
     * @param String                method
     * 
     * @return Object
     */
    call( bearerToken, endpoint, data = null, method = 'post' ) {
        return this.fetch( this.resolveUrl( endpoint ), {
            method,
            // If data
            ...( data ? { body: JSON.stringify( data ) } : {} ),
            headers: {
                'Authorization': `Bearer ${ bearerToken }`,
                // If data
                ...( data ? { 'Content-Type': 'application/json' } : {} ),
            },
        } ).then( res => res.ok ? res.json() : Promise.reject( `${ res.status } - ${ res.statusText }` ) );
    }

    /**
     * Decodes data from a signed JWT.
     *
     * @param String                token
     * @param Object                params
     * 
     * @return Object|Undefined
     */
    jwtVerify( token, params = {} ) {
        return new Promise( ( resolve, reject ) => {
            let publicKey = this.jwtokens.publicKey;
            if ( !publicKey && this.jwtokens.jwksUrl ) {
                publicKey = ( header, callback ) => {
                    const jwksClient = JwksClient( { jwksUri: this.resolveUrl( this.jwtokens.jwksUrl ), } );
                    jwksClient.getSigningKey( header.kid, ( err, key ) => {
                        if ( err ) return callback( err, null );
                        const signingKey = key.publicKey || key.rsaPublicKey;
                        callback( null, signingKey );
                    } );
                };
            }
            if ( !publicKey ) throw new Error( `A provider must be initialized with a "config.jwtokens.publicKey" or "config.jwtokens.publicKeyUrl" parameter to verify ID Tokens.` );
            this.jwt.verify( token, publicKey, {
                complete: true,
                // Verify audience claims - "token.payload.aud" - usually client_id
                audience: this.clientId,
                // Verify issuer claims - "token.payload.iss" - usually this.baseUrl (But must end as a path: "url/")
                issuer: this.baseUrl,
                // Verify signing algorithm - "token.header.alg" - HS256, RS256
                algorithms: [ 'RS256', 'HS256' ],
                // Verify expiration - (auto) "token.payload.exp" - must be after the current date/time
                // Verify permissions (scopes) - "token.payload.scopes" - from the initiator request
                ...this.jwtokens,
                ...params,
            }, ( error, decoded ) => error ? reject( error ) : resolve( decoded ));
        } );
    }

    /**
     * Decodes data from a signed JWT.
     *
     * @param String                token
     * 
     * @return Object|Undefined
     */
    jwtDecode( token ) {
        return this.jwt.decode( token, { complete: true } );
    }
    
}