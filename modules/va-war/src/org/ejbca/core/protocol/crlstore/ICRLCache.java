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
package org.ejbca.core.protocol.crlstore;

import org.cesecore.certificates.certificate.HashID;

/**
 * An implementation of this is managing a cache of Certificates. The implementation should be optimized for quick lookups of CRLs that the 
 * VA responder needs to fetch.
 * 
 * @author Lars Silven PrimeKey
 * 
 * @version $Id$
 */
public interface ICRLCache {

	/**
	 * @param id The ID of the issuer DN.
	 * @param isDelta true if delta CRL
	 * @return  array of X509Certificate or null if no CRLs exist in the cache.
	 */
	byte[] findLatestByIssuerDN(HashID id, boolean isDelta);

	/**
	 * @param id The ID of the subject key identifier.
	 * @param isDelta true if delta CRL
	 * @return CRL or null if the CRL does not exist in the cache.
	 */
	byte[] findBySubjectKeyIdentifier(HashID id, boolean isDelta);
}
