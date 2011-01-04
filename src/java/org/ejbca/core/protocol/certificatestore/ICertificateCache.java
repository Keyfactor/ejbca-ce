/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.certificatestore;

import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.CertificateID;

/**
 * An implementation of this is managing a cache of Certificates. The implementation should be optimized for quick lookups of CA certificates that the 
 * OCSP responder needs to fetch.
 * 
 * @author Lars Silven PrimeKey
 * 
 * @version $Id$
 */
public interface ICertificateCache {

	/**
	 * @param id The ID of the subject DN.
	 * @return X509Certificate or null if the certificate does not exist in the cache.
	 */
	X509Certificate findLatestBySubjectDN(HashID id);

	/**
	 * @param id The ID of the issuer DN.
	 * @return  array of X509Certificate or null if no certificates exist in the cache.
	 */
	X509Certificate[] findLatestByIssuerDN(HashID id);

	/**
	 * @param id The ID of the subject key identifier.
	 * @return X509Certificate or null if the certificate does not exist in the cache.
	 */
	X509Certificate findBySubjectKeyIdentifier(HashID id);

	/** Finds a certificate in a collection based on the OCSP issuerNameHash and issuerKeyHash
	 * 
	 * @param certId CertificateId from the OCSP request
	 * @param certs the collection of CA certificate to search through
	 * @return X509Certificate A CA certificate or null of not found in the collection
	 */
	X509Certificate findByOcspHash(CertificateID certId);

	/**
	 * @return All root certificates.
	 */
	X509Certificate[] getRootCertificates();

	/** Method used to force reloading of the certificate cache. Can be triggered by an external event for example.
	 */
	void forceReload();

}