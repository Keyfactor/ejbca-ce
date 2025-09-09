/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp.cache;

import java.math.BigInteger;

import org.cesecore.certificates.certificate.CertificateStatus;

import jakarta.ejb.Local;

@Local
public interface OcspRequestSignerStatusCacheSingletonLocal {

    /**
     * Create a cache lookup key with very low probability of collision.
     * 
     * @param signercertIssuerName Issuer DN of the certificate that signed the OCSP request
     * @param signercertSerNo Serial number of the certificate that signed the OCSP request
     * @return a key that can be used for cache lookup
     */
    String createCacheLookupKey(String signercertIssuerName, BigInteger signercertSerNo);

    /** @return a usable CertificateStatus or null of the cache needs an update for this entry. */
    CertificateStatus getCachedCertificateStatus(String cacheLookupKey);

    /** Update the cache with an usable CertificateStatus. */
    void updateCachedCertificateStatus(String cacheLookupKey, CertificateStatus certificateStatus);

    /** Clear cache. */
    void flush();

}