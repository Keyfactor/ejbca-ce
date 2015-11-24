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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.config.OcspConfiguration;

/**
 * Cache of revocation status for certificates that signs OCSP requests.
 * 
 * @version $Id$
 */
public enum OcspRequestSignerStatusCache {
    INSTANCE;

    /** Cache entry keeping track of a revocation status and when it was last updated. */
    private class OcspSignerStatus {
        long lastUpdate;
        final CertificateStatus certificateStatus;
        
        public OcspSignerStatus(final long lastUpdate, final CertificateStatus certificateStatus) {
            this.lastUpdate = lastUpdate;
            this.certificateStatus = certificateStatus;
        }
    }

    private final Map<String, OcspSignerStatus> cache = new ConcurrentHashMap<String, OcspSignerStatus>();

    /**
     * Create a cache lookup key with very low probability of collision.
     * 
     * @param signercertIssuerName Issuer DN of the certificate that signed the OCSP request
     * @param signercertSerNo Serial number of the certificate that signed the OCSP request
     * @return a key that can be used for cache lookup
     */
    public String createCacheLookupKey(final String signercertIssuerName, final BigInteger signercertSerNo) {
        return Integer.toHexString(signercertIssuerName.hashCode()) + ";" + signercertSerNo.toString(16);
    }

    /** @return a usable CertificateStatus or null of the cache needs an update for this entry. */
    public CertificateStatus getCachedCertificateStatus(final String cacheLookupKey) {
        final OcspSignerStatus ocspSignerStatus = cache.get(cacheLookupKey);
        if (ocspSignerStatus==null) {
            return null;
        }
        final long now = System.currentTimeMillis();
        final long cacheTime = OcspConfiguration.getRequestSigningCertRevocationCacheTimeMs();
        if (ocspSignerStatus.lastUpdate+cacheTime<=now) {
            // Current thread will be forced to update cache, but the rest will continue with slightly stale data
            ocspSignerStatus.lastUpdate=now;
            return null;
        }
        return ocspSignerStatus.certificateStatus;
    }

    /** Update the cache with an usable CertificateStatus. */
    public void updateCachedCertificateStatus(final String cacheLookupKey, final CertificateStatus certificateStatus) {
        if (certificateStatus==null) {
            cache.remove(cacheLookupKey);
        } else {
            final long now = System.currentTimeMillis();
            final OcspSignerStatus ocspSignerStatus = cache.get(cacheLookupKey);
            if (ocspSignerStatus!=null && ocspSignerStatus.certificateStatus.equals(certificateStatus)) {
                // Status was unchanged, so just update when we checked this
                ocspSignerStatus.lastUpdate = now;
            } else {
                cache.put(cacheLookupKey, new OcspSignerStatus(now, certificateStatus));
            }
        }
    }

    /** Clear cache. */
    public void flush() {
        cache.clear();
    }
}
