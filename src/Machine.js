
/**
 * @imports
 */
import Jsonwebtoken from 'jsonwebtoken';

/**
 * Machine Object
 */
export default class Machine {

    /**
     * Initializes a Machine instance
     * 
     * @param String    baseUrl
     * @param Function  fetch
     */
    constructor( { baseUrl, fetch } ) {
        Object.defineProperty( this, 'baseUrl', { value: !baseUrl.endsWith( '/' ) ? baseUrl + '/' : baseUrl } );
        this.fetch = fetch;
        this.jwt = Jsonwebtoken;
    }

     /**
     * Resolves an URL against baseUrl
     * 
     * @param String    url
     * 
     * @return String
     */
    resolveUrl( url ) {
        return url && (
            url.startsWith( 'https://' ) || url.startsWith( 'http://' ) ? url 
            : `${ this.baseUrl }${ url.startsWith('/') ? url.substring( 1 ) : url }`
        );
    }

}