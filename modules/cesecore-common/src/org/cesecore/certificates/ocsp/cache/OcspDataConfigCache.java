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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;

import com.keyfactor.util.CertTools;

/**
 * Cache holding performance sensitive CA configuration required by OCSP lookups
 * @version $Id$
 *
 */
public enum OcspDataConfigCache {
    INSTANCE;
    
    private final static Logger log = Logger.getLogger(OcspDataConfigCache.class);
    
    private Map<Integer, OcspDataConfigCacheEntry> cache = new HashMap<>();
    private Map<Integer, OcspDataConfigCacheEntry> staging = new HashMap<>();
    private Boolean isCaModeCompatiblePresent = false;
    private Boolean isCaModeCompatibleStagingValue = false;

    /**
     * @param certID CertificateId to lookup in cache
     * @return Cache entry related to the given CertificateId
     */
    public OcspDataConfigCacheEntry getEntry(final CertificateID certID) {
        return cache.get(getCacheIdFromCertificateID(certID));
    }
    
    /**
     * Adds a cache entry to the cache. Invocation may add multiple entries since we support more than 
     * one AlgorithmIdentifier for OCSP.
     * @param ocspPreProductionConfigCacheEntry cache entry to add
     */
    public void stagingAdd(OcspDataConfigCacheEntry ocspPreProductionConfigCacheEntry) {
        final List<CertificateID> certIDs = ocspPreProductionConfigCacheEntry.getCertificateID();
        for (CertificateID certID : certIDs) {
            // CertificateID doesn't have a unique identifier. Construct one using issue hashes
            staging.put(getCacheIdFromCertificateID(certID), ocspPreProductionConfigCacheEntry);            
        }
    }

    /** Clears the staging cache from old entries. Invoke before populating the staging cache */
    public void stagingStart() {
        staging = new HashMap<>();
        isCaModeCompatibleStagingValue = false;
    }
    
    /** Commits the staged cache to the live one. Invoke when staging cache is considered ready. */
    public void stagingCommit() {
        cache = staging;
        staging = new HashMap<>();
        isCaModeCompatiblePresent = isCaModeCompatibleStagingValue;
        isCaModeCompatibleStagingValue = false;
    }
    
    /**
     * We currently support SHA1 and SHA256 AlgorithmIdentifiers. Hence the list.
     * @return the CertificateID's based on the provided certificate. 
     */
    static List<CertificateID> getCertificateIdFromCertificate(final X509Certificate certificate) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Building CertificateId's from certificate with subjectDN '" + CertTools.getSubjectDN(certificate) + "'.");
            }
            final List<CertificateID> ret = new ArrayList<>();
            ret.add(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), certificate, certificate.getSerialNumber()));
            ret.add(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), certificate, certificate.getSerialNumber()));
            return ret;
        } catch (OCSPException | CertificateEncodingException | OperatorCreationException e) {
            throw new OcspFailureException(e);
        }
    }
    
    /** @return Cache identifier based on the provided CertificateID. */
    private static int getCacheIdFromCertificateID(final CertificateID certID) {
        // Use bitwise XOR of the hashcodes for IssuerNameHash and IssuerKeyHash to produce the integer.
        final BigInteger issuerNameHash = bigIntFromBytes(certID.getIssuerNameHash());
        final BigInteger issuerKeyHash = bigIntFromBytes(certID.getIssuerKeyHash());
        int result = issuerNameHash.hashCode() ^ issuerKeyHash.hashCode();
        if (log.isDebugEnabled()) {
            log.debug("Using getIssuerNameHash " + issuerNameHash.toString(16) + " and getIssuerKeyHash "
                    + issuerKeyHash.toString(16) + " to produce id " + result);
        }
        return result;
    }
    
    private static BigInteger bigIntFromBytes(final byte[] bytes) {
        if (ArrayUtils.isEmpty(bytes)) {
            return BigInteger.valueOf(0);
        }
        return new BigInteger(bytes);
    }

    public Boolean getCaModeCompatiblePresent() {
        return isCaModeCompatiblePresent;
    }

    public void setCaModeCompatiblePresent(Boolean caModeCompatiblePresent) {
        isCaModeCompatibleStagingValue = caModeCompatiblePresent;
    }
}
