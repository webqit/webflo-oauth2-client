
/**
 * @imports
 */
import { _from as _arrFrom } from '@webqit/util/arr/index.js';

/**
 * Resolves a scope array, or a space-delimited scope string to an array.
 * 
 * @param String|Array  scope 
 * 
 * @return Array
 */
export function scopeSplit( scope ) {
    return  _arrFrom( scope ).reduce( ( arr, str ) => arr.concat( str.split( ' ' ).map( s => s.trim() ) ), [] );
}

/**
 * Base64-URL-encodes a string.
 * 
 * @param String  str 
 * 
 * @return String
 */
export function base64URLEncode( str ) {
    return str.toString( 'base64' ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=/g, '' );
}