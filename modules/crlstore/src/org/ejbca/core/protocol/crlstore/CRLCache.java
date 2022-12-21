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
import java.util.Objects;
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
 */
public class CRLCache {
	private static final Logger log = Logger.getLogger(CRLCache.class);
	
    private static CRLCache instance = null;
    private static final Lock lock = new ReentrantLock();
	
	private final CrlStoreSessionLocal crlStoreSession;
	private final CaCertificateCache certCache;
	private final Map<Integer, CRLEntity> crls = new HashMap<>();
	private final Map<Integer, CRLEntity> deltaCrls = new HashMap<>();
	private class CRLEntity {
		final CRLInfo crlInfo;
		final byte[] encoded;
		/**
		 * @param crlInfo
		 * @param encoded
		 */
		CRLEntity(CRLInfo crlInfo, byte[] encoded) {
			super();
			this.crlInfo = crlInfo;
			this.encoded = encoded;
		}

		@Override
		public boolean equals(Object o) {
			if (o == this)
				return true;
			if (!(o instanceof CRLEntity)) {
				return false;
			}
			CRLEntity crlEntity = (CRLEntity) o;
			return Objects.equals(crlInfo.getSubjectDN(), crlEntity.crlInfo.getSubjectDN()) && crlInfo.getCrlPartitionIndex() == crlEntity.crlInfo.getCrlPartitionIndex();
		}

		@Override
		public int hashCode() {
			// Ignore CRL number. Always overwrite cache with latest CRL for the partition.
			return Objects.hash(crlInfo.getSubjectDN(), crlInfo.getCrlPartitionIndex());
		}

	}
	/** We need an object to synchronize around when rebuilding and reading the cache. When rebuilding the cache no thread
	 * can be allowed to read the cache, since the cache will be in an inconsistent state. In the normal case we want to use
	 * as fast objects as possible (HashMap) for reading fast.
	 */
	private final Lock rebuildlock = new ReentrantLock();

	 /**
     * @return  {@link CRLCache} for the CA.
     */
     public static CRLCache getInstance(CrlStoreSessionLocal crlDataSession, CaCertificateCache certCache) {
         if (instance != null) {
             return instance;
         }
         lock.lock();
         try {
             if (instance == null) {
                 instance = new CRLCache(crlDataSession, certCache);
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
	private CRLCache(CrlStoreSessionLocal crlStoreSession, CaCertificateCache certCache) {
		super();
		this.crlStoreSession = crlStoreSession;
		this.certCache = certCache;
	}

	/**
     * @param id The ID of the subject key identifier.
     * @param isDelta true if delta CRL
     * @param crlNumber specific crlNumber of the CRL to be retrieved, when not the latest, or -1 for the latest
     * @return CRL or null if the CRL does not exist in the cache.
     */
	public byte[] findBySubjectKeyIdentifier(HashID id, int crlPartitionIndex, boolean isDelta, int crlNumber) {
		return findCRL(certCache.findBySubjectKeyIdentifier(id), crlPartitionIndex, isDelta, crlNumber);
	}

	/**
     * @param id The ID of the issuer DN.
     * @param isDelta true if delta CRL
     * @param crlNumber specific crlNumber of the CRL to be retrieved, when not the latest, or -1 for the latest
     * @return CRL or null if the CRL does not exist in the cache.
     */
	public byte[] findByIssuerDN(HashID id, int crlPartitionIndex, boolean isDelta, int crlNumber) {
		return findCRL(certCache.findLatestBySubjectDN(id), crlPartitionIndex, isDelta, crlNumber);
	}

	private byte[] findCRL(final X509Certificate caCert, final int crlPartitionIndex, final boolean isDelta, final int crlNumber) {
		if ( caCert==null ) {
			if (log.isDebugEnabled()) {
				log.debug("No CA certificate, returning null.");
			}
			return new byte[0];
		}
		final String issuerDN = CertTools.getSubjectDN(caCert);
		this.rebuildlock.lock();
		try {
			final CRLInfo crlInfo = this.crlStoreSession.getLastCRLInfo(issuerDN, crlPartitionIndex, isDelta);
			if ( crlInfo==null ) {
				if (log.isDebugEnabled()) {
					log.debug("No CRL found with issuerDN '"+issuerDN+"', returning null.");
				}
				return new byte[0];
			}
			final Integer cacheId = new CRLEntity(crlInfo, null).hashCode();
            final Map<Integer, CRLEntity> usedCrls = isDelta ? this.deltaCrls : this.crls;
			// If we have not specified a crlNumber we can try to find the latest CRL in the cache
			if (crlNumber == -1) {
			    final CRLEntity cachedCRL = usedCrls.get(cacheId);
			    if ( cachedCRL!=null && !crlInfo.getCreateDate().after(cachedCRL.crlInfo.getCreateDate()) ) {
			        if (log.isDebugEnabled()) {
			            log.debug("Retrieved CRL (from cache) with issuerDN '"+issuerDN+"', with CRL number "+crlInfo.getLastCRLNumber() + " and partition " + crlInfo.getCrlPartitionIndex());
			        }
			        return cachedCRL.encoded;
			    }
			}
			final CRLEntity entry;
			if (crlNumber > -1) {
			    if (log.isDebugEnabled()) {
			        log.debug("Getting CRL with CRL number "+crlNumber);
			    }
			    entry = new CRLEntity( crlInfo, this.crlStoreSession.getCRL(issuerDN, crlPartitionIndex, crlNumber) );
			} else {
			    entry = new CRLEntity( crlInfo, this.crlStoreSession.getLastCRL(issuerDN, crlPartitionIndex, isDelta) );
			    // Only cache latest CRLs, these should be the ones accessed regularly, and we don't want to fill the cache with old CRLs
	            usedCrls.put(cacheId, entry);
			}
			if (log.isDebugEnabled()) {
				log.debug("Retrieved CRL (not from cache) with issuerDN '"+issuerDN+"', with CRL number "+crlInfo.getLastCRLNumber() + " and partition " + crlInfo.getCrlPartitionIndex());
			}
			return entry.encoded;
		} finally {
			this.rebuildlock.unlock();
		}
	}
}
