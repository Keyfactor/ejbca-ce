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
 * See {@link ICRLCache} to see what this is.
 * @author lars
 * @version $Id$
 */
class CRLCache implements ICRLCache {
	private static final Logger log = Logger.getLogger(CRLCache.class);
	
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
	 * @param crlSession DB connections
	 * @param certStore references to needed CA certificates.
	 */
	CRLCache(CrlStoreSessionLocal crlSession, CaCertificateCache certCache) {
		super();
		this.crlSession = crlSession;
		this.certCache = certCache;
	}

	@Override
	public byte[] findBySubjectKeyIdentifier(HashID id, boolean isDelta) {
		return findLatest(this.certCache.findBySubjectKeyIdentifier(id), isDelta);
	}

	@Override
	public byte[] findLatestByIssuerDN(HashID id, boolean isDelta) {
		return findLatest(this.certCache.findLatestBySubjectDN(id), isDelta);
	}

	private byte[] findLatest(X509Certificate caCert, boolean isDelta) {
		if ( caCert==null ) {
			if (log.isDebugEnabled()) {
				log.debug("No caCert, returning null.");
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
			final CRLEntity cachedCRL = usedCrls.get(id.getKey());
			if ( cachedCRL!=null && !crlInfo.getCreateDate().after(cachedCRL.crlInfo.getCreateDate()) ) {
				if (log.isDebugEnabled()) {
					log.debug("Retrieved CRL (from cache) with issuerDN '"+issuerDN+"', with CRL number "+crlInfo.getLastCRLNumber());
				}
				return cachedCRL.encoded;
			}
			final CRLEntity entry = new CRLEntity( crlInfo, this.crlSession.getLastCRL(issuerDN, isDelta) );
			usedCrls.put(id.getKey(), entry);
			if (log.isDebugEnabled()) {
				log.debug("Retrieved CRL (not from cache) with issuerDN '"+issuerDN+"', with CRL number "+crlInfo.getLastCRLNumber());
			}
			return entry.encoded;
		} finally {
			this.rebuildlock.unlock();
		}
	}
}
