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
    
    // Logger is not static since static initializers run after the constructor for enums.
	private final Logger log = Logger.getLogger(CaCertificateCache.class);

    /** Mapping from subjectDN to key in the certs HashMap. */
    private Map<Integer, X509Certificate> certsFromSubjectDN = new HashMap<>();
    /** Mapping from issuerDN to key in the certs HashMap. */
    private Map<Integer, Set<X509Certificate>> certsFromIssuerDN = new HashMap<>();
    /** Mapping from subject key identifier to key in the certs HashMap. */
    private Map<Integer, X509Certificate> certsFromSubjectKeyIdentifier = new HashMap<>();
    /** All root certificates. */
    private Set<X509Certificate> rootCertificates = new HashSet<>();

	/** Cache time counter, set and used by loadCertificates */
	private long certValidTo = 0;

    public X509Certificate findLatestBySubjectDN(final HashID id) {
        final X509Certificate ret = certsFromSubjectDN.get(id.getKey());
        if (ret==null && log.isDebugEnabled()) {
            log.debug("Certificate not found from SubjectDN HashId in certsFromSubjectDN map. HashID=" + id.getB64());
        }
        return ret;
	}

	public X509Certificate[] findLatestByIssuerDN(final HashID id) {	    
        final Set<X509Certificate> sCert = certsFromIssuerDN.get(id.getKey());
        if (sCert == null || sCert.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Certificate not found from IssuerDN HashId in certsFromIssuerDN map. HashID=" + id.getB64());
            }
            return null;
        }
        return sCert.toArray(new X509Certificate[sCert.size()]);

    }

    public X509Certificate[] getRootCertificates() {
        return rootCertificates.toArray(new X509Certificate[0]);
    }

    public X509Certificate findBySubjectKeyIdentifier(final HashID id) {
        final X509Certificate ret = certsFromSubjectKeyIdentifier.get(id.getKey());
        if (ret==null && log.isDebugEnabled()) {
            log.debug("Certificate not found from SubjectKeyIdentifier HashId in certsFromSubjectKeyIdentifier map. HashID=" + id.getB64());
        }
        return ret;
    }

    public boolean isCacheExpired() {
        return certValidTo < System.currentTimeMillis();
    }

	/** Loads the CA certificate cache  with a bunch of certificates.
	 *
	 * We keep this method as synchronized to avoid ConcurrentModificationException, it should not take more than a few microseconds to complete.
	 * We also only want one single thread to do the cache rebuilding.
	 * Only X509Certificates will be considered and other types, as well as invalid coded certificates, will be ignored.
	 * 
	 * @param certs A collection of X509Certificates to put in the CA certificate cache, if empty or null the cache will be emptied
	 */
    public synchronized void loadCertificates(final Collection<Certificate> certs) {
        if (log.isDebugEnabled()) {
            log.debug("Loaded " + (certs == null ? "0" : Integer.toString(certs.size())) + " ca certificates");
        }

        Map<Integer, X509Certificate> newCertsFromSubjectDN = new HashMap<>();
        Map<Integer, Set<X509Certificate>> newCertsFromIssuerDN = new HashMap<>();
        Map<Integer, X509Certificate> newCertsFromSubjectKeyIdentifier = new HashMap<>();
        Set<X509Certificate> newRootCertificates = new HashSet<>();
        if (certs != null) {
            for (final Certificate tmp : certs) {
                if (!(tmp instanceof X509Certificate)) {
                    log.debug("Not adding CA certificate of type: " + tmp.getType());
                    continue;
                }
                final X509Certificate cert = (X509Certificate) tmp;
                try { // test if certificate is OK. we have experienced that BC could decode a certificate that later on could not be used.
                    final Integer key = HashID.getFromKeyID(cert).getKey();
                    final X509Certificate pastCert = newCertsFromSubjectKeyIdentifier.get(key);
                    final Date notBefore = CertTools.getNotBefore(cert);
                    if (notBefore == null) {
                        log.debug("CA certificate with serial '" + CertTools.getSerialNumberAsString(cert)  + "' does not have notBefore attribute and will not be added");
                        continue;
                    }
                    // Add the entry if it's the first, or if it is more recent than the one existing (in that case replace it)
                    if (pastCert == null || notBefore.after(CertTools.getNotBefore(pastCert))) {
                        newCertsFromSubjectKeyIdentifier.put(key, cert);
                    }
                } catch (Throwable t) { // NOPMD: catch all to not break with an error here.
                    if (log.isDebugEnabled()) {
                        final StringWriter sw = new StringWriter();
                        final PrintWriter pw = new PrintWriter(sw);
                        pw.println("Erroneous certificate fetched from database.");
                        pw.println("The public key can not be extracted from the certificate.");
                        pw.println("Here follows a base64 encoding of the certificate:");
                        try {
                            final String b64encoded = new String(Base64.encode(cert.getEncoded()));
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
                final Integer subjectDNKey = HashID.getFromSubjectDN(cert).getKey();
                // Check if we already have a certificate from this issuer in the HashMap.
                // We only want to store the latest cert from each issuer in this map
                final X509Certificate pastCert = newCertsFromSubjectDN.get(subjectDNKey);
                final boolean isLatest;
                if (pastCert != null) {
                    if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(pastCert))) {
                        isLatest = true;
                    } else {
                        isLatest = false;
                    }
                } else {
                    isLatest = true;
                }
                if (isLatest) {
                    newCertsFromSubjectDN.put(subjectDNKey, cert);
                    final Integer issuerDNKey = HashID.getFromIssuerDN(cert).getKey();
                    if (!issuerDNKey.equals(subjectDNKey)) { // don't add roots to themselves
                        Set<X509Certificate> sIssuer = newCertsFromIssuerDN.get(issuerDNKey);
                        if (sIssuer == null) {
                            sIssuer = new HashSet<>();
                            newCertsFromIssuerDN.put(issuerDNKey, sIssuer);
                        }
                        sIssuer.add(cert);
                        sIssuer.remove(pastCert);
                    } else {
                        newRootCertificates.add(cert);
                        newRootCertificates.remove(pastCert);
                    }
                }
            }
        }
        // Log what we have stored in the cache
        if (log.isDebugEnabled()) {
            final StringWriter sw = new StringWriter();
            final PrintWriter pw = new PrintWriter(sw, true);
            pw.println("Found the following CA certificates :");
            for (Entry<Integer, X509Certificate> key : newCertsFromSubjectKeyIdentifier.entrySet()) {
                final Certificate cert = key.getValue();
                pw.print(CertTools.getSubjectDN(cert));
                pw.print(',');
                pw.println(CertTools.getSerialNumberAsString(cert));
            }
            log.debug(sw);
        }
        //Replace the old caches
        certsFromSubjectKeyIdentifier = newCertsFromSubjectKeyIdentifier;
        certsFromIssuerDN = newCertsFromIssuerDN;
        certsFromSubjectDN = newCertsFromSubjectDN;
        rootCertificates = newRootCertificates;
        certValidTo = System.currentTimeMillis() + OcspConfiguration.getSigningCertsValidTimeInMilliseconds();
    }
}
