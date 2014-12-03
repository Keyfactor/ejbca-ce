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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.ocsp.CertificateID;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.util.CertTools;

/**
 * Hold information needed for creating an OCSP response without database lookups.
 * 
 * @version $Id$
 */
public class OcspSigningCacheEntry {

    private final List<CertificateID> certificateID;
    private final List<X509Certificate> caCertificateChain;
    private final X509Certificate ocspSigningCertificate;
    private final List<X509Certificate> fullCertificateChain;
    private final transient PrivateKey privateKey;
    private final String signatureProviderName;
    private final OcspKeyBinding ocspKeyBinding;
    private final X509Certificate issuerCaCertificate;

    public OcspSigningCacheEntry(X509Certificate issuerCaCertificate, List<X509Certificate> signingCaCertificateChain, X509Certificate ocspSigningCertificate, PrivateKey privateKey,
            String signatureProviderName, OcspKeyBinding ocspKeyBinding) {
        this.caCertificateChain = signingCaCertificateChain;
        this.ocspSigningCertificate = ocspSigningCertificate;
        if (ocspSigningCertificate == null) {
            fullCertificateChain = signingCaCertificateChain;
        } else {
            fullCertificateChain = new ArrayList<X509Certificate>();
            fullCertificateChain.add(ocspSigningCertificate);
            fullCertificateChain.addAll(signingCaCertificateChain);
        }
        this.privateKey = privateKey;
        this.signatureProviderName = signatureProviderName;
        this.ocspKeyBinding = ocspKeyBinding;
        this.issuerCaCertificate = issuerCaCertificate;
        this.certificateID = OcspSigningCache.getCertificateIDFromCertificate(issuerCaCertificate);
    }

    public List<CertificateID> getCertificateID() { return certificateID; }
    public List<X509Certificate> getCaCertificateChain() { return caCertificateChain; }
    public X509Certificate getOcspSigningCertificate() { return ocspSigningCertificate; }
    public List<X509Certificate> getFullCertificateChain() { return fullCertificateChain; }
    public PrivateKey getPrivateKey() { return privateKey; }
    public String getSignatureProviderName() { return signatureProviderName; }
    public OcspKeyBinding getOcspKeyBinding() { return ocspKeyBinding; }
    /**
     * Checks if the entry has a OCSP signing certificate separate from the certificate chain.
     * Only entries with a keybinding can have a separate certificate.
     * */
    public boolean isUsingSeparateOcspSigningCertificate() { return ocspSigningCertificate != null; }
    
    public boolean isPlaceholder() { return privateKey == null; }

    public X509Certificate getIssuerCaCertificate() {
        return issuerCaCertificate;
    }
}
