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

package org.cesecore.certificates.ca.internal;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;


/**
 * A cache for storing CA certificates
 *
 * @version $Id$
 *
 */
public enum CaCertificateCache  {
    INSTANCE;
    
	/** Log4j instance for Base */
	private static final Logger log = Logger.getLogger(CaCertificateCache.class);

	/** Mapping from subjectDN to key in the certs HashMap. */
	final private Map<Integer, X509Certificate> certsFromSubjectDN = new HashMap<Integer, X509Certificate>();
	/** Mapping from issuerDN to key in the certs HashMap. */
	final private Map<Integer, Set<X509Certificate>> certsFromIssuerDN = new HashMap<Integer, Set<X509Certificate>>();
	/** Mapping from subject key identifier to key in the certs HashMap. */
	final private Map<Integer, X509Certificate> certsFromSubjectKeyIdentifier = new HashMap<Integer, X509Certificate>();
	/** All root certificates. */
	final private Set<X509Certificate> rootCertificates = new HashSet<X509Certificate>();

	/** The interval in milliseconds on which new OCSP signing certs are loaded. */
	final private int m_valid_time = OcspConfiguration.getSigningCertsValidTimeInMilliseconds();

	/** Cache time counter, set and used by loadCertificates */
	private long m_certValidTo = 0;

	/** We need an object to synchronize around when rebuilding and reading the cache. When rebuilding the cache no thread
	 * can be allowed to read the cache, since the cache will be in an inconsistent state. In the normal case we want to use
	 * as fast objects as possible (HashMap) for reading fast.
	 */
	final private ReentrantLock rebuildlock = new ReentrantLock();

	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.certificatestore.ICertificateCache#findLatestBySubjectDN(org.ejbca.core.protocol.ocsp.HashID)
	 */
	public X509Certificate findLatestBySubjectDN(HashID id) {

		// Keep the lock as small as possible, but do not try to read the cache while it is being rebuilt
        while (rebuildlock.isLocked()) {
            try {
                wait(100);
            } catch (InterruptedException e) {
                throw new IllegalStateException("Interrupted while waiting for build lock to release", e);
            }
        }

        X509Certificate ret = this.certsFromSubjectDN.get(id.key);
        if ((ret == null) && log.isDebugEnabled()) {
            log.debug("Certificate not found from SubjectDN HashId in certsFromSubjectDN map. HashID=" + id.b64);
        }
        return ret;

	}
	
	public X509Certificate[] findLatestByIssuerDN(HashID id) {
        while (rebuildlock.isLocked()) {
            try {
                wait(100);
            } catch (InterruptedException e) {
                throw new IllegalStateException("Interrupted while waiting for build lock to release", e);
            }
        }

        final Set<X509Certificate> sCert = this.certsFromIssuerDN.get(id.key);
        if (sCert == null || sCert.size() < 1) {
            if (log.isDebugEnabled()) {
                log.debug("Certificate not found from IssuerDN HashId in certsFromIssuerDN map. HashID=" + id.b64);
            }
            return null;
        }
        return sCert.toArray(new X509Certificate[sCert.size()]);

    }

    public X509Certificate[] getRootCertificates() {
        while (rebuildlock.isLocked()) {
            try {
                wait(100);
            } catch (InterruptedException e) {
                throw new IllegalStateException("Interrupted while waiting for build lock to release", e);
            }
        }
        return this.rootCertificates.toArray(new X509Certificate[0]);
    }

    public X509Certificate findBySubjectKeyIdentifier(HashID id) {
        while (rebuildlock.isLocked()) {
            try {
                wait(100);
            } catch (InterruptedException e) {
                throw new IllegalStateException("Interrupted while waiting for build lock to release", e);
            }
        }
        X509Certificate ret = this.certsFromSubjectKeyIdentifier.get(id.key);
        if ((ret == null) && log.isDebugEnabled()) {
            log.debug("Certificate not found from SubjectKeyIdentifier HashId in certsFromSubjectKeyIdentifier map. HashID=" + id.b64);
        }
        return ret;
    }

    public boolean isCacheExpired() {
        return this.m_certValidTo > new Date().getTime();
    }

	/** Loads CA certificates but holds a cache so it's reloaded only every five minutes (configurable).
	 *
	 * We keep this method as synchronized, it should not take more than a few microseconds to complete if the cache does not have
	 * to be reloaded. If the cache must be reloaded, we must wait for it anyway to not have ConcurrentModificationException.
	 * We also only want one single thread to do the rebuilding.
	 */
	public void loadCertificates(final Collection<Certificate> certs) {
		this.rebuildlock.lock();
		try {
			if (log.isDebugEnabled()) {
				log.debug("Loaded "+(certs == null ? "0":Integer.toString(certs.size()))+" ca certificates");
			}
			// Set up certsFromSubjectDN, certsFromSHA1CertId and certCache
			this.certsFromSubjectDN.clear();
			this.certsFromIssuerDN.clear();
			this.certsFromSubjectKeyIdentifier.clear();
			this.rootCertificates.clear();
			for(final Certificate tmp  : certs) {
				if ( !(tmp instanceof X509Certificate) ) {
					log.debug("Not adding CA certificate of type: "+tmp.getType());
					continue;
				}
				final X509Certificate cert = (X509Certificate)tmp;
	            try { // test if certificate is OK. we have experienced that BC could decode a certificate that later on could not be used.
					this.certsFromSubjectKeyIdentifier.put(HashID.getFromKeyID(cert).key, cert);
	            } catch ( Throwable t ) { // NOPMD: catch all to not break with an error here.
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
			} 

            // Log what we have stored in the cache
            if (log.isDebugEnabled()) {
                final StringWriter sw = new StringWriter();
                final PrintWriter pw = new PrintWriter(sw, true);
                pw.println("Found the following CA certificates :");
                for (Entry<Integer, X509Certificate> key : certsFromSubjectKeyIdentifier.entrySet()) {
                    final Certificate cert = key.getValue();
                    pw.print(CertTools.getSubjectDN(cert));
                    pw.print(',');
                    pw.println(CertTools.getSerialNumberAsString(cert));
                }
                log.debug(sw);
            }
            this.m_certValidTo = new Date().getTime()+this.m_valid_time;
		} finally {
			this.rebuildlock.unlock();
		}
	} // loadCertificates

}
