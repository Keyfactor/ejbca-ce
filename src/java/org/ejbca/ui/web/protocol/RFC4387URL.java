/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import org.cesecore.certificates.certificate.HashID;


/**
 * Create RFC4387 URLs and HTML references to such URLs. 
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public enum RFC4387URL {
	sHash,
	iHash,
	sKIDHash;
	private String getID(HashID hash, boolean isDelta, boolean isHTML) {
		final String theAmp = isHTML ? "&amp;" : "&";
		final String deltaParam = isDelta ? theAmp+"delta=" : "";
		return hash.getB64url() + deltaParam;
	}
	private String appendQueryToURL(String url, String id) {
		return url+"?"+this.toString()+"="+id;
	}
	/**
	 * Append the query of the RFC hash to a URL
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @param isDelta true if it is a link to a delta CRL.
	 * @return URL to fetch certificate or CRL.
	 */
	public String appendQueryToURL(String url, HashID hash, boolean isDelta) {
		final String id = getID(hash, isDelta, false);
		return appendQueryToURL(url, id);
	}
	/**
	 * See {@link #appendQueryToURL(String, HashID, boolean)}, isDelta is false.
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @return URL to fetch certificate or CRL.
	 */
	public String appendQueryToURL(String url, HashID hash) {
		return appendQueryToURL(url, hash, false);
	}
	/**
	 * HTML string that show the reference to fetch a certificate or CRL.
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @param isDelta true if it is a link to a delta CRL.
	 * @return URL to fetch certificate or CRL.
	 */
	public String getRef(String url, HashID hash, boolean isDelta) {
		final String resURL = appendQueryToURL(url, getID(hash, isDelta, true));
		return this.toString()+" = "+hash.getB64()+(isDelta ? " delta":"")+" <a href=\""+resURL+"\">Download</a>";
	}
	/**
	 * See {@link #getRef(String, HashID, boolean)}, isDelta is false.
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @return URL to fetch certificate or CRL.
	 */
	public String getRef(String url, HashID hash) {
		return getRef(url, hash, false);
	}
}
