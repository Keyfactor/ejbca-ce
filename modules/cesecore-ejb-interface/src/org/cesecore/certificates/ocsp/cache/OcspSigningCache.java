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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.util.CertTools;

/**
 * Hold information needed to create OCSP responses without database lookups.
 * 
 * @version $Id$
 */
public enum OcspSigningCache {
    INSTANCE;

    private Map<Integer,OcspSigningCacheEntry> cache = new HashMap<Integer, OcspSigningCacheEntry>();
    private Map<Integer,OcspSigningCacheEntry> staging = new HashMap<Integer, OcspSigningCacheEntry>();
    private OcspSigningCacheEntry defaultResponderCacheEntry = null;
    private final ReentrantLock lock = new ReentrantLock(false);
    private final static Logger log = Logger.getLogger(OcspSigningCache.class);
    
    /**
     * 
     * 
     * @param id the ID of the sought entry
     * @return the sought entry, null otherwise.
     */
    public OcspSigningCacheEntry getEntry(final int id) {
        return cache.get(id);
    }
    
    public OcspSigningCacheEntry getEntry(final CertificateID certID) {
        return cache.get(getCacheIdFromCertificateID(certID));
    }
    
    public OcspSigningCacheEntry getDefaultEntry() {
        return defaultResponderCacheEntry;
    }

    /** WARNING: This method potentially exports references to CAs private keys! */
    public Collection<OcspSigningCacheEntry> getEntries() {
        return cache.values();
    }
    
    public void stagingStart() {
        lock.lock();
        staging = new HashMap<Integer, OcspSigningCacheEntry>();
    }

    public void stagingAdd(OcspSigningCacheEntry ocspSigningCacheEntry) {
        staging.put(getCacheIdFromCertificateID(ocspSigningCacheEntry.getCertificateID()), ocspSigningCacheEntry);
    }

    public void stagingCommit() {
        OcspSigningCacheEntry defaultResponderCacheEntry = null;
        for (final OcspSigningCacheEntry entry : staging.values()) {
            
            if (entry.getOcspSigningCertificate() == null) {
                final X509Certificate signingCertificate = entry.getCaCertificateChain().get(0);
                if(CertTools.getSubjectDN(signingCertificate).equals(OcspConfiguration.getDefaultResponderId())) {
                    defaultResponderCacheEntry = entry;
                    break;
                }
            } else {
                final X509Certificate signingCertificate = entry.getOcspSigningCertificate();
                if(CertTools.getIssuerDN(signingCertificate).equals(OcspConfiguration.getDefaultResponderId())) {
                    defaultResponderCacheEntry = entry;
                    break;
                }
            }
        }
        if (defaultResponderCacheEntry == null) {
            log.info("Default OCSP responder with subject '" + OcspConfiguration.getDefaultResponderId() + "' was not found."+
                    " OCSP requests for certificates issued by unknown CAs will fail with response code 2 (internal error).");
            if (staging.values().size() > 0) {
                // We could pick a responder at chance here, but it may be a feature to the user to not waste HSM signatures on Unknown responses..
                log.info("No default OCSP responder has been configured. OCSP requests for certificates issued by unknown CAs "+
                        "will fail with response code 2 (internal error).");
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Committing the following to OCSP cache:");
            for (final Integer key : staging.keySet()) {
                final OcspSigningCacheEntry entry = staging.get(key);
                log.debug(" KeyBindingId: " + key + ", SubjectDN '" + CertTools.getSubjectDN(entry.getFullCertificateChain().get(0))+"', IssuerDN '"+CertTools.getIssuerDN(entry.getFullCertificateChain().get(0))+"', SerialNumber "+entry.getFullCertificateChain().get(0).getSerialNumber().toString()+"/"+entry.getFullCertificateChain().get(0).getSerialNumber().toString(16));
                if (entry.getOcspKeyBinding() != null) {
                    log.debug("   keyPairAlias: " + entry.getOcspKeyBinding().getKeyPairAlias());
                }
            }
        }
        cache = staging;
        this.defaultResponderCacheEntry = defaultResponderCacheEntry;
    }

    public void stagingRelease() {
        lock.unlock();
    }

    /** @return a cache identifier based on the provided CertificateID. */
    public static int getCacheIdFromCertificateID(final CertificateID certID) {
        // Use bitwise XOR of the hashcodes for IssuerNameHash and IssuerKeyHash to produce the integer.
        int result = new BigInteger(certID.getIssuerNameHash()).hashCode() ^ new BigInteger(certID.getIssuerKeyHash()).hashCode();
        if (log.isDebugEnabled()) {
            log.debug("Using getIssuerNameHash " + new BigInteger(certID.getIssuerNameHash()).toString(16) + " and getIssuerKeyHash " + new BigInteger(certID.getIssuerKeyHash()).toString(16) + " to produce id " + result);
        }
        return result;
    }
    
    /** @return the CertificateID based on the provided certificate */
    public static CertificateID getCertificateIDFromCertificate(final X509Certificate certificate) {
        try {
            return new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), certificate, certificate.getSerialNumber());
        } catch (OCSPException e) {
            throw new OcspFailureException(e);
        } catch (CertificateEncodingException e) {
            throw new OcspFailureException(e);
        }
    }
}
