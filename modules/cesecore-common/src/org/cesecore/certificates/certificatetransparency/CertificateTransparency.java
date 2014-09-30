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
package org.cesecore.certificates.certificatetransparency;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.cesecore.certificates.certificateprofile.CertificateProfile;

/**
 * X509CA will attempt to load org.cesecore.certificates.certificatetransparency.CertificateTransparencyImpl
 * that must implement this interface if it exists.
 * 
 * The reason why this is an interface is because the CT support is a separate feature not
 * included in standard EJBCA.
 * 
 * @version $Id$
 */
public interface CertificateTransparency {

    String SCTLIST_OID = "1.3.6.1.4.1.11129.2.4.2";
    
    /**
     * Overloaded method that with allLogs = false
     * 
     * @throws CTLogException If too many servers are down to satisfy the certificate profile.
     *
     * @see CertificateTransparency#fetchSCTList(List, CertificateProfile, Map, boolean)
     */
    byte[] fetchSCTList(List<Certificate> chain, CertificateProfile certProfile, Map<Integer,CTLogInfo> configuredCTLogs) throws CTLogException;
    
    /**
     * Tries to add a certificate to CT logs and obtain SCTs (Signed Certificate Timestamps).
     * The configuration is taken from the certificate profile.
     * 
     * @param chain Certificate chain including any CT signer and the leaf pre-certificate
     * @param certProfile Certificate profile with CT configuration
     * @param configuredCTLogs Contains definitions (URL, public key, etc.) of the logs that can be used. 
     * @param allLogs If true the certificate will be submitted to all enabled logs, otherwise the limit in the certificate profile is taken into account.
     * @return A "SCT List" structure, for inclusion in e.g. the CT certificate extension, or null if no logs have been configured.
     * @throws CTLogException If too many servers are down to satisfy the certificate profile.
     */
    byte[] fetchSCTList(List<Certificate> chain, CertificateProfile certProfile, Map<Integer,CTLogInfo> configuredCTLogs, boolean allLogs) throws CTLogException;
    
    /**
     * Tries to add a certificate to CT logs and obtain SCTs (Signed Certificate Timestamps).
     * 
     * @param chain Certificate chain including any CT signer and the leaf pre-certificate
     * @param logs The logs to connect to.
     * @param timeout HTTP request timeout in milliseconds. 
     * @param minSCTs The number of SCTs to require
     * @param maxRetries Maximum number of retries
     * @return A "SCT List" structure, for inclusion in e.g. the CT certificate extension
     * @throws CTLogException If too many servers are down to satisfy the certificate profile.
     */
    byte[] fetchSCTList(List<Certificate> chain, Collection<CTLogInfo> ctlogs, int minSCTs, int maxSCTs, int maxRetries) throws CTLogException;
    
    /**
     * Adds a critical extension to prevent the certificate from being used
     */
    void addPreCertPoison(X509v3CertificateBuilder precertbuilder);
    
    /**
     * Replaces wildcards in DNS-ID in the SubjectAlternativeName with "(PRIVATE)" and adds the necessary extension
     */
    void handleSubjectAltNameExtension(X509v3CertificateBuilder certbuilder, X509v3CertificateBuilder precertbuilder, Extension subAltNameExtension) throws CertIOException;
    
    /**
     * Returns true if the given certificate has an SCT extension with at least one entry. 
     */
    boolean hasSCTs(Certificate cert);
    
}
