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

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;

/**
 * An implementation of this is managing a cache of CRLs. The implementation should be optimized for quick lookups of CRLs that the 
 * VA responder needs to fetch.
 *
 * @version $Id$
 */
public class CRLCache {
	private static final Logger log = Logger.getLogger(CRLCache.class);
	
    private static CRLCache instance = null;
    private static final Lock lock = new ReentrantLock();
	
	private final CrlStoreSessionLocal crlSession;
	private final CaCertificateCache certCache;
	final private Map<Integer, CRLEntity> crls = new HashMap<Integer, CRLEntity>();
	final private Map<Integer, CRLEntity> deltaCrls = new HashMap<Integer, CRLEntity>();
	private class CRLEntity {
		final CRLInfo crlInfo;
		final byte encoded[];
		/**
		 * @param crlInfo
		 * @param encoded
		 */
		CRLEntity(CRLInfo crlInfo, byte[] encoded) {
			super();
			this.crlInfo = crlInfo;
			this.encoded = encoded;
		}
	}
	/** We need an object to synchronize around when rebuilding and reading the cache. When rebuilding the cache no thread
	 * can be allowed to read the cache, since the cache will be in an inconsistent state. In the normal case we want to use
	 * as fast objects as possible (HashMap) for reading fast.
	 */
	final private Lock rebuildlock = new ReentrantLock();

	 /**
     * @return  {@link CRLCache} for the CA.
     */
    public static CRLCache getInstance(CrlStoreSessionLocal crlSession, CaCertificateCache certCache) {
        if (instance != null) {
            return instance;
        }
        lock.lock();
        try {
            if ( instance==null ) {
                instance = new CRLCache(crlSession, certCache);
            }
            return instance;
        } finally {
            lock.unlock();
        }
    }
	
	/**
	 * @param crlSession reference to CRLStoreSession
	 * @param certStore references to needed CA certificates.
	 */
	private CRLCache(CrlStoreSessionLocal crlSession, CaCertificateCache certCache) {
		super();
		this.crlSession = crlSession;
		this.certCache = certCache;
	}

	/**
     * @param id The ID of the subject key identifier.
     * @param isDelta true if delta CRL
     * @param crlNumber specific crlNumber of the CRL to be retrieved, when not the latest, or -1 for the latest
     * @return CRL or null if the CRL does not exist in the cache.
     */
	public byte[] findBySubjectKeyIdentifier(HashID id, boolean isDelta, int crlNumber) {
		return findCRL(certCache.findBySubjectKeyIdentifier(id), isDelta, crlNumber);
	}

	/**
     * @param id The ID of the issuer DN.
     * @param isDelta true if delta CRL
     * @param crlNumber specific crlNumber of the CRL to be retrieved, when not the latest, or -1 for the latest
     * @return CRL or null if the CRL does not exist in the cache.
     */
	public byte[] findByIssuerDN(HashID id, boolean isDelta, int crlNumber) {
		return findCRL(certCache.findLatestBySubjectDN(id), isDelta, crlNumber);
	}

	private byte[] findCRL(X509Certificate caCert, boolean isDelta, int crlNumber) {
		if ( caCert==null ) {
			if (log.isDebugEnabled()) {
				log.debug("No CA certificate, returning null.");
			}
			return null;
		}
		final HashID id = HashID.getFromSubjectDN(caCert);
		final String issuerDN = CertTools.getSubjectDN(caCert);
		this.rebuildlock.lock();
		try {
			final CRLInfo crlInfo = this.crlSession.getLastCRLInfo(issuerDN, isDelta);
			if ( crlInfo==null ) {
				if (log.isDebugEnabled()) {
					log.debug("No CRL found with issuerDN '"+issuerDN+"', returning null.");
				}
				return null;
			}
            final Map<Integer, CRLEntity> usedCrls = isDelta ? this.deltaCrls : this.crls;
			// If we have not specified a crlNumber we can try to find the latest CRL in the cache
			if (crlNumber == -1) {
			    final CRLEntity cachedCRL = usedCrls.get(id.getKey());
			    if ( cachedCRL!=null && !crlInfo.getCreateDate().after(cachedCRL.crlInfo.getCreateDate()) ) {
			        if (log.isDebugEnabled()) {
			            log.debug("Retrieved CRL (from cache) with issuerDN '"+issuerDN+"', with CRL number "+crlInfo.getLastCRLNumber());
			        }
			        return cachedCRL.encoded;
			    }
			}
			final CRLEntity entry;
			if (crlNumber > -1) {
			    if (log.isDebugEnabled()) {
			        log.debug("Getting CRL with CRL number "+crlNumber);
			    }
			    entry = new CRLEntity( crlInfo, this.crlSession.getCRL(issuerDN, crlNumber) );			    
			} else {
			    entry = new CRLEntity( crlInfo, this.crlSession.getLastCRL(issuerDN, isDelta) );
			    // Only cache latest CRLs, these should be the ones accessed regularly, and we don't want to fill the cache with old CRLs
	            usedCrls.put(id.getKey(), entry);
			}
			if (log.isDebugEnabled()) {
				log.debug("Retrieved CRL (not from cache) with issuerDN '"+issuerDN+"', with CRL number "+crlInfo.getLastCRLNumber());
			}
			return entry.encoded;
		} finally {
			this.rebuildlock.unlock();
		}
	}
}
