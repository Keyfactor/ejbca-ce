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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.util.CertTools;
import org.cesecore.util.Base64;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.SecConst;


/**
 * See {@link ICertificateCache} to see what this is.
 *
 * @version $Id$
 *
 */
class CertificateCache implements ICertificateCache {

	/** Log4j instance for Base */
	private static final Logger log = Logger.getLogger(CertificateCache.class);

	/** Mapping from subjectDN to key in the certs HashMap. */
	final private Map<Integer, X509Certificate> certsFromSubjectDN = new HashMap<Integer, X509Certificate>();
	/** Mapping from OCSP CertificateID to key in the certs HashMap. */
	final private Map<Integer, X509Certificate> certsFromOcspCertId = new HashMap<Integer, X509Certificate>();
	/** Mapping from issuerDN to key in the certs HashMap. */
	final private Map<Integer, Set<X509Certificate>> certsFromIssuerDN = new HashMap<Integer, Set<X509Certificate>>();
	/** Mapping from subject key identifier to key in the certs HashMap. */
	final private Map<Integer, X509Certificate> certsFromSubjectKeyIdentifier = new HashMap<Integer, X509Certificate>();
	/** All root certificates. */
	final private Set<X509Certificate> rootCertificates = new HashSet<X509Certificate>();

	/** The interval in milliseconds on which new OCSP signing certs are loaded. */
	final private int m_valid_time = OcspConfiguration.getSigningCertsValidTime();

	/** A collection that can be used to JUnit test this class. Set responder type to OCSPUtil.RESPONDER_TYPE_TEST
	 * and give a Collection of CA certificate in the initialization properties.
	 */
	final private Collection<Certificate> testcerts;

	final private CertificateStoreSessionLocal certificateStoreSession;

	/** Cache time counter, set and used by loadCertificates */
	private long m_certValidTo = 0;

	/** We need an object to synchronize around when rebuilding and reading the cache. When rebuilding the cache no thread
	 * can be allowed to read the cache, since the cache will be in an inconsistent state. In the normal case we want to use
	 * as fast objects as possible (HashMap) for reading fast.
	 */
	final private Lock rebuildlock = new ReentrantLock();

	/**
	 * @param certificateStoreSession The DB store to be used.
	 */
	CertificateCache(CertificateStoreSessionLocal certificateStoreSession) {
		// Default values
		this.testcerts = null;
		this.certificateStoreSession = certificateStoreSession;
		loadCertificates();
	}

	/**
	 * @param _testcerts can be set to null or be a collection of test certificates
	 */
	CertificateCache(Collection<Certificate> _testcerts) {
		// Default values
		this.certificateStoreSession = null;
		this.testcerts = _testcerts;
		loadCertificates();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#findLatestBySubjectDN(org.ejbca.core.protocol.ocsp.HashID)
	 */
	public X509Certificate findLatestBySubjectDN(HashID id) {
		loadCertificates(); // refresh cache?

		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			X509Certificate ret = this.certsFromSubjectDN.get(id.key);
			if ((ret == null) && log.isDebugEnabled()) {
				log.debug("Certificate not found from SubjectDN HashId in certsFromSubjectDN map. HashID="+id.b64);
			}
			return ret;
		} finally {
			this.rebuildlock.unlock();
		}
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#findLatestByIssuerDN(org.ejbca.core.protocol.ocsp.HashID)
	 */
	public X509Certificate[] findLatestByIssuerDN(HashID id) {
		loadCertificates(); // refresh cache?

		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			final Set<X509Certificate> sCert = this.certsFromIssuerDN.get(id.key);
			if ( sCert==null || sCert.size()<1 ) {
				if (log.isDebugEnabled()) {
					log.debug("Certificate not found from IssuerDN HashId in certsFromIssuerDN map. HashID="+id.b64);
				}
				return null;
			}
			return sCert.toArray(new X509Certificate[0]);
		} finally {
			this.rebuildlock.unlock();
		}
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#findByHash(org.bouncycastle.ocsp.CertificateID)
	 */
	public X509Certificate findByOcspHash(CertificateID certId) {
		if (null == certId) {
			throw new IllegalArgumentException();
		}
		loadCertificates(); // refresh cache?

		// See if we have it in one of the certificate caches
		final Integer key =  keyFromCertificateID(certId);
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		try {
			this.rebuildlock.lock();
			final X509Certificate ret = this.certsFromOcspCertId.get(key);
			if (ret == null) {
				if (log.isDebugEnabled()) {
					log.debug("Certificate not found from CertificateID in SHA1CertId map.");
				}
				return null;
			}
			if (log.isDebugEnabled()) {
				log.debug("Found certificate from CertificateID in cache. SubjectDN='"+ CertTools.getSubjectDN(ret)+"', serno="+CertTools.getSerialNumberAsString(ret) + ", IssuerKeyHash=" + new String(Hex.encode(certId.getIssuerKeyHash())));
			}
			return ret;
		} finally {
			this.rebuildlock.unlock();
		}
	}
	
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#getRootCertificates()
	 */
	@Override
	public X509Certificate[] getRootCertificates() {
		loadCertificates(); // refresh cache?
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			return this.rootCertificates.toArray(new X509Certificate[0]);
		} finally {
			this.rebuildlock.unlock();
		}
		
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#forceReload()
	 */
	public void forceReload() {
		this.m_certValidTo = 0;
		loadCertificates();
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#findBySubjectKeyIdentifier(org.ejbca.core.protocol.certificatestore.HashID)
	 */
	@Override
	public X509Certificate findBySubjectKeyIdentifier(HashID id) {
		loadCertificates(); // refresh cache?
		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
		this.rebuildlock.lock();
		try {
			X509Certificate ret = this.certsFromSubjectKeyIdentifier.get(id.key);
			if ((ret == null) && log.isDebugEnabled()) {
				log.debug("Certificate not found from SubjectKeyIdentifier HashId in certsFromSubjectKeyIdentifier map. HashID="+id.b64);
			}
			return ret;
		} finally {
			this.rebuildlock.unlock();
		}
	}
	
	/* private helper methods */

	private Integer keyFromCertificateID(CertificateID certID) {
		return new Integer(new BigInteger(certID.getIssuerNameHash()).hashCode()^new BigInteger(certID.getIssuerKeyHash()).hashCode());
	}
	/** Loads CA certificates but holds a cache so it's reloaded only every five minutes (configurable).
	 *
	 * We keep this method as synchronized, it should not take more than a few microseconds to complete if the cache does not have
	 * to be reloaded. If the cache must be reloaded, we must wait for it anyway to not have ConcurrentModificationException.
	 * We also only want one single thread to do the rebuilding.
	 */
	private void loadCertificates() {
		this.rebuildlock.lock();
		try {
			// Check if we have a cached collection that is not too old
			if ( !this.certsFromSubjectDN.isEmpty() && this.m_certValidTo > new Date().getTime()) {
				// The other HashMaps are always created as well, if this one is created
				return;
			}
			final Collection<Certificate> certs = findCertificatesByType(SecConst.CERTTYPE_SUBCA + SecConst.CERTTYPE_ROOTCA, null);
			if (log.isDebugEnabled()) {
				log.debug("Loaded "+(certs == null ? "0":Integer.toString(certs.size()))+" ca certificates");
			}
			if ( certs==null ) {
				log.fatal("findCertificatesByType returns null. This should never happen!");
				return;
			}
			// Set up certsFromSubjectDN, certsFromSHA1CertId and certCache
			this.certsFromSubjectDN.clear();
			this.certsFromOcspCertId.clear();
			this.certsFromIssuerDN.clear();
			this.certsFromSubjectKeyIdentifier.clear();
			this.rootCertificates.clear();
			final Iterator<Certificate> i = certs.iterator();
			while (i.hasNext()) {
				final Certificate tmp = i.next();
				if ( !(tmp instanceof X509Certificate) ) {
					log.debug("Not adding CA certificate of type: "+tmp.getType());
					continue;
				}
				final X509Certificate cert = (X509Certificate)tmp;
	            try { // test if certificate is OK. we have experienced that BC could decode a certificate that later on could not be used.
					this.certsFromSubjectKeyIdentifier.put(HashID.getFromKeyID(cert).key, cert);
	            } catch ( Throwable t ) {
	            	if ( log.isDebugEnabled() ) {
		            	final StringWriter sw = new StringWriter();
		            	final PrintWriter pw = new PrintWriter(sw);
		            	pw.println("Erroneous certificate fetched from database.");
		            	pw.println("The public key can not be extracted from the certificate.");
		            	pw.println("Here follows a base64 encoding of the certificate:");
						try {
			            	final String b64encoded = new String( Base64.encode(cert.getEncoded()) );
			            	pw.println(CertTools.BEGIN_CERTIFICATE);
			            	pw.println(b64encoded);
			            	pw.println(CertTools.END_CERTIFICATE);
						} catch (CertificateEncodingException e) {
							pw.println("Not possible to encode certificate.");
						}
		            	pw.flush();
		            	log.debug(sw.toString());
	            	}
            		continue;
	            }
				final Integer subjectDNKey = HashID.getFromSubjectDN(cert).key;
				// Check if we already have a certificate from this issuer in the HashMap.
				// We only want to store the latest cert from each issuer in this map
				final X509Certificate pastCert = this.certsFromSubjectDN.get(subjectDNKey);
				final boolean isLatest;
				if ( pastCert!=null ) {
					if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(pastCert))) {
						isLatest = true;
					} else {
						isLatest = false;
					}
				} else {
					isLatest = true;
				}
				if ( isLatest ) {
					this.certsFromSubjectDN.put(subjectDNKey, cert);
					final Integer issuerDNKey = HashID.getFromIssuerDN(cert).key;
					if ( !issuerDNKey.equals(subjectDNKey) ) { // don't add root to them self
						Set<X509Certificate> sIssuer = this.certsFromIssuerDN.get(issuerDNKey);
						if ( sIssuer==null ) {
							sIssuer = new HashSet<X509Certificate>();
							this.certsFromIssuerDN.put(issuerDNKey, sIssuer);
						}
						sIssuer.add(cert);
						sIssuer.remove(pastCert);
					} else {
						this.rootCertificates.add(cert);
						this.rootCertificates.remove(pastCert);
					}
				}
				// We only need issuerNameHash and issuerKeyHash from certId
				try {
					final CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, cert, new BigInteger("1"));
					this.certsFromOcspCertId.put(keyFromCertificateID(certId), cert);
				} catch (OCSPException e) {
					log.warn(e);
				}
			} // while (i.hasNext()) {

			// Log what we have stored in the cache
			if (log.isDebugEnabled()) {
				final StringWriter sw = new StringWriter();
				final PrintWriter pw = new PrintWriter(sw,true);
				final Set<Entry<Integer, X509Certificate>> certEntrys = this.certsFromSubjectKeyIdentifier.entrySet();
				final Iterator<Entry<Integer, X509Certificate>> iter = certEntrys.iterator();
				pw.println("Found the following CA certificates :");
				while (iter.hasNext()) {
					final Entry<Integer, X509Certificate> key = iter.next();
					final Certificate cert = key.getValue();
					pw.print(CertTools.getSubjectDN(cert));
					pw.print(',');
					pw.println(CertTools.getSerialNumberAsString(cert));
				}
				log.debug(sw);
			}
			// If m_valid_time == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
			this.m_certValidTo = this.m_valid_time>0 ? new Date().getTime()+this.m_valid_time : Long.MAX_VALUE;
		} finally {
			this.rebuildlock.unlock();
		}
	} // loadCertificates

	/**
	 *
	 * @param adm
	 * @param type
	 * @param issuerDN
	 * @return Collection of Certificate never null
	 */
	private Collection<Certificate> findCertificatesByType(int type, String issuerDN) {
		if ( this.certificateStoreSession==null ) {
			// Use classes CertificateCacheStandalone or CertificateCacheInternal for non-test caches
			return this.testcerts;
		}
		return this.certificateStoreSession.findCertificatesByType(type, issuerDN);
	}
}
