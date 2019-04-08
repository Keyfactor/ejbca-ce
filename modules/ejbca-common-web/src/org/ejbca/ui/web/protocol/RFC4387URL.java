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

import org.cesecore.certificates.certificate.CertificateConstants;
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
	private String getID(HashID hash, int crlPartitionIndex, boolean isDelta, boolean isHTML) {
		final String theAmp = isHTML ? "&amp;" : "&";
		final StringBuilder sb = new StringBuilder();
		sb.append(hash.getB64url());
		if (isDelta) {
		    sb.append(theAmp);
		    sb.append("delta=");
		}
		if (crlPartitionIndex != CertificateConstants.NO_CRL_PARTITION) {
		    sb.append(theAmp);
            sb.append("partition=");
            sb.append(crlPartitionIndex);
		}
		return sb.toString();
	}
	private String appendQueryToURL(String url, String id) {
        return url+"?"+toString()+"="+id;
	}
	/**
	 * Append the query of the RFC hash to a URL
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @param crlPartitionIndex CRL Partition, or {@link CertificateConstants#NO_CRL_PARTITION}. Should always be {@link CertificateConstants#NO_CRL_PARTITION} for certificates.
	 * @param isDelta true if it is a link to a delta CRL.
	 * @return URL to fetch certificate or CRL.
	 */
	public String appendQueryToURL(String url, HashID hash, int crlPartitionIndex, boolean isDelta) {
		final String id = getID(hash, crlPartitionIndex, isDelta, false);
		return appendQueryToURL(url, id);
	}
	/**
	 * See {@link #appendQueryToURL(String, HashID, int, boolean)}, isDelta is false, and partitioned CRLs cannot be requested.
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @return URL to fetch certificate or CRL.
	 */
	public String appendQueryToURL(String url, HashID hash) {
		return appendQueryToURL(url, hash, CertificateConstants.NO_CRL_PARTITION, false);
	}
	/**
	 * HTML string that show the reference to fetch a certificate or CRL.
	 * @param url The URL except the query
	 * @param hash of the object to fetch
	 * @param isDelta true if it is a link to a delta CRL.
	 * @return URL to fetch certificate or CRL.
	 */
	public String getRef(String url, HashID hash, boolean isDelta) {
		final String resURL = appendQueryToURL(url, getID(hash, CertificateConstants.NO_CRL_PARTITION, isDelta, true));
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
