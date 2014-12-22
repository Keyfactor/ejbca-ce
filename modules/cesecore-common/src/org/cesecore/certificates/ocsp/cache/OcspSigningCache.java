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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.lang.StringUtils;
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
import org.cesecore.util.CertTools;

/**
 * Hold information needed to create OCSP responses without database lookups.
 * 
 * @version $Id$
 */
public enum OcspSigningCache {
    INSTANCE;
    
    private Map<Integer, OcspSigningCacheEntry> cache = new HashMap<Integer, OcspSigningCacheEntry>();
    private Map<Integer, OcspSigningCacheEntry> staging = new HashMap<Integer, OcspSigningCacheEntry>();
    private OcspSigningCacheEntry defaultResponderCacheEntry = null;
    private final ReentrantLock lock = new ReentrantLock(false);
    private final static Logger log = Logger.getLogger(OcspSigningCache.class);
    /** Flag to cache if we have logged the existence of a default responder */
    private volatile boolean loggedDefaultResponder = false;
    /** Flag to cache if we have logged the non-existence of a default responder */
    private volatile boolean loggedNoDefaultResponder = false;
    
    public OcspSigningCacheEntry getEntry(final CertificateID certID) {
        return cache.get(getCacheIdFromCertificateID(certID));
    }

    /**
     * 
     * @return the entry corresponding to the default responder, or null if it wasn't found.
     */
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
        List<CertificateID> certIDs = ocspSigningCacheEntry.getCertificateID();
        for (CertificateID certID : certIDs) {
            staging.put(getCacheIdFromCertificateID(certID), ocspSigningCacheEntry);            
        }
    }

    public void stagingCommit(final String defaultResponderSubjectDn) {
        OcspSigningCacheEntry defaultResponderCacheEntry = null;
        for (final OcspSigningCacheEntry entry : staging.values()) {
            if (entry.getOcspSigningCertificate() != null) {
                final X509Certificate signingCertificate = entry.getOcspSigningCertificate();
                if (CertTools.getIssuerDN(signingCertificate).equals(defaultResponderSubjectDn)) {
                    defaultResponderCacheEntry = entry;
                    if (!loggedDefaultResponder) {
                        log.info("Setting keybinding with ID" + entry.getOcspKeyBinding().getId() + " and DN " + defaultResponderSubjectDn
                                + " as default OCSP responder.");
                        loggedDefaultResponder = true; // we should only log this once, unless status changes
                    }
                    break;
                }
            } else if (entry.getCaCertificateChain() != null && !entry.getCaCertificateChain().isEmpty()) {
                final X509Certificate signingCertificate = entry.getCaCertificateChain().get(0);
                if (CertTools.getSubjectDN(signingCertificate).equals(defaultResponderSubjectDn)) {
                    defaultResponderCacheEntry = entry;
                    if (!loggedDefaultResponder) {
                        log.info("Setting CA with DN " + defaultResponderSubjectDn + " as default OCSP responder.");
                        loggedDefaultResponder = true; // we should only log this once, unless status changes
                    }
                    break;
                }
            }
        }
        if (defaultResponderCacheEntry == null) {
            if (!loggedNoDefaultResponder) {
                String msg;
                if (StringUtils.isEmpty(defaultResponderSubjectDn)) {
                    msg = "No default responder was defined.";
                } else {
                    msg = "The default OCSP responder with subject '" + defaultResponderSubjectDn + "' was not found.";
                }
                msg += " OCSP requests for certificates issued by unknown CAs will return \"unauthorized\" as per RFC6960, Section 2.3";
                log.info(msg);
                loggedNoDefaultResponder = true; // we should only log this once, unless status changes
            }
            loggedDefaultResponder = false; // if we get a default responder again, log it
        } else {
            loggedNoDefaultResponder = false; // if we lose a default responder again, log it
        }
        //Lastly, walk through the list of entries and replace all placeholders with the default responder
        Map<Integer, OcspSigningCacheEntry> modifiedEntries = new HashMap<Integer, OcspSigningCacheEntry>();
        List<Integer> removedEntries = new ArrayList<Integer>();
        for (Integer key : staging.keySet()) {
            OcspSigningCacheEntry entry = staging.get(key);
            //If entry has been created without a private key, replace it with the default responder.
            if (entry.isPlaceholder()) {
                if (defaultResponderCacheEntry != null) {
                    entry = new OcspSigningCacheEntry(entry.getIssuerCaCertificate(), entry.getIssuerCaCertificateStatus(),
                            defaultResponderCacheEntry.getCaCertificateChain(), defaultResponderCacheEntry.getOcspSigningCertificate(),
                            defaultResponderCacheEntry.getPrivateKey(), defaultResponderCacheEntry.getSignatureProviderName(),
                            defaultResponderCacheEntry.getOcspKeyBinding());
                    modifiedEntries.put(key, entry);
                } else {
                    //If no default responder is defined, remove placeholder. 
                    removedEntries.add(key);
                }
            }
        }
        staging.putAll(modifiedEntries);
        for (Integer removedKey : removedEntries) {
            staging.remove(removedKey);
        }
        cache = staging;
        this.defaultResponderCacheEntry = defaultResponderCacheEntry;
        if (log.isDebugEnabled()) {
            log.debug("Committing the following to OCSP cache:");
            for (final Integer key : staging.keySet()) {
                final OcspSigningCacheEntry entry = staging.get(key);
                log.debug(" KeyBindingId: " + key + ", SubjectDN '" + CertTools.getSubjectDN(entry.getFullCertificateChain().get(0))
                        + "', IssuerDN '" + CertTools.getIssuerDN(entry.getFullCertificateChain().get(0)) + "', SerialNumber "
                        + entry.getFullCertificateChain().get(0).getSerialNumber().toString() + "/"
                        + entry.getFullCertificateChain().get(0).getSerialNumber().toString(16));
                if (entry.getOcspKeyBinding() != null) {
                    log.debug("   keyPairAlias: " + entry.getOcspKeyBinding().getKeyPairAlias());
                }
            }
        }
    }

    public void stagingRelease() {
        lock.unlock();
    }

    /**
     * This method will add a single cache entry to the cache. It should only be used to solve temporary cache inconsistencies.
     * 
     * @param ocspSigningCacheEntry the entry to add
     */
    public void addSingleEntry(OcspSigningCacheEntry ocspSigningCacheEntry) {
        List<CertificateID> certIDs = ocspSigningCacheEntry.getCertificateID();
        for (CertificateID certID : certIDs) {
            int cacheId = getCacheIdFromCertificateID(certID);
            lock.lock();
            try {
                //Make sure that another thread didn't add the same entry while this one was waiting.
                if (!cache.containsKey(cacheId)) {
                    cache.put(cacheId, ocspSigningCacheEntry);
                }
            } finally {
                lock.unlock();
            }
        }
    }

    /** @return a cache identifier based on the provided CertificateID. */
    public static int getCacheIdFromCertificateID(final CertificateID certID) {
        // Use bitwise XOR of the hashcodes for IssuerNameHash and IssuerKeyHash to produce the integer.
        int result = new BigInteger(certID.getIssuerNameHash()).hashCode() ^ new BigInteger(certID.getIssuerKeyHash()).hashCode();
        if (log.isDebugEnabled()) {
            log.debug("Using getIssuerNameHash " + new BigInteger(certID.getIssuerNameHash()).toString(16) + " and getIssuerKeyHash "
                    + new BigInteger(certID.getIssuerKeyHash()).toString(16) + " to produce id " + result);
        }
        return result;
    }

    /** @return the CertificateID's based on the provided certificate */
    public static List<CertificateID> getCertificateIDFromCertificate(final X509Certificate certificate) {
        try {
            if (log.isTraceEnabled()) {
                log.trace("Building CertificateId's from certificate with subjectDN '" + CertTools.getSubjectDN(certificate) + "'.");
            }
            List<CertificateID> ret = new ArrayList<CertificateID>();
            ret.add(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), certificate, certificate.getSerialNumber()));
            ret.add(new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), certificate, certificate.getSerialNumber()));
            return ret;
        } catch (OCSPException e) {
            throw new OcspFailureException(e);
        } catch (CertificateEncodingException e) {
            throw new OcspFailureException(e);
        } catch (OperatorCreationException e) {
            throw new OcspFailureException(e);
        }
    }
}
