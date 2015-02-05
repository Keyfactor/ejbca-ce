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

import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.util.CertTools;

/**
 * Hold information needed for creating an OCSP response without database lookups.
 * 
 * @version $Id$
 */
public class OcspSigningCacheEntry {

    private static final Logger log = Logger.getLogger(OcspSigningCacheEntry.class);
    
    private final List<CertificateID> certificateID;
    private final List<X509Certificate> caCertificateChain;
    private final X509Certificate ocspSigningCertificate;
    private final List<X509Certificate> fullCertificateChain;
    private final X509Certificate signingCertificate;
    private final transient PrivateKey privateKey;
    private final String signatureProviderName;
    private final OcspKeyBinding ocspKeyBinding;
    private final X509Certificate issuerCaCertificate;
    private final CertificateStatus issuerCaCertificateStatus;
    private boolean responseSignatureVerified = false;
    private final int responderIdType;
    private RespID respId;
    private final X509Certificate[] responseCertChain;
    private final boolean signingCertificateForOcspSigning;

    public OcspSigningCacheEntry(X509Certificate issuerCaCertificate, CertificateStatus issuerCaCertificateStatus,
            List<X509Certificate> signingCaCertificateChain, X509Certificate ocspSigningCertificate, PrivateKey privateKey,
            String signatureProviderName, OcspKeyBinding ocspKeyBinding, int responderIdType) {
      this.caCertificateChain = signingCaCertificateChain;
        this.ocspSigningCertificate = ocspSigningCertificate;
        if (ocspSigningCertificate == null) {
            fullCertificateChain = signingCaCertificateChain;
        } else {
            fullCertificateChain = new ArrayList<X509Certificate>();
            fullCertificateChain.add(ocspSigningCertificate);
            fullCertificateChain.addAll(signingCaCertificateChain);
        }
        if (fullCertificateChain==null) {
            signingCertificate = null;
        } else {
            signingCertificate = fullCertificateChain.get(0);
        }
        this.privateKey = privateKey;
        this.signatureProviderName = signatureProviderName;
        this.ocspKeyBinding = ocspKeyBinding;
        this.issuerCaCertificate = issuerCaCertificate;
        this.certificateID = OcspSigningCache.getCertificateIDFromCertificate(issuerCaCertificate);
        this.issuerCaCertificateStatus = issuerCaCertificateStatus;
        this.responderIdType = responderIdType;
        if (signingCertificate==null) {
            respId = null;
            signingCertificateForOcspSigning = true;
        } else {
            if (responderIdType == OcspConfiguration.RESPONDERIDTYPE_NAME) {
                respId = new JcaRespID(signingCertificate.getSubjectX500Principal());
            } else {
                try {
                    respId = new JcaRespID(signingCertificate.getPublicKey(), SHA1DigestCalculator.buildSha1Instance());
                } catch (OCSPException e) {
                    log.warn("Unable to contruct responder Id of type 'hash', falling back to using 'name' as responder Id.", e);
                    respId = new JcaRespID(signingCertificate.getSubjectX500Principal());
                }
            }
            if (ocspSigningCertificate==null) {
                signingCertificateForOcspSigning = true;    // CA cert
            } else {
                signingCertificateForOcspSigning = CertTools.isOCSPCert(signingCertificate);
            }
        }
        if (fullCertificateChain==null) {
            responseCertChain = null;
        } else {
            responseCertChain = getResponseCertChain(fullCertificateChain.toArray(new X509Certificate[0]));
        }
    }

    public List<CertificateID> getCertificateID() { return certificateID; }
    public List<X509Certificate> getCaCertificateChain() { return caCertificateChain; }
    public X509Certificate getOcspSigningCertificate() { return ocspSigningCertificate; }
    public List<X509Certificate> getFullCertificateChain() { return fullCertificateChain; }
    public X509Certificate getSigningCertificate() { return signingCertificate; }
    public PrivateKey getPrivateKey() { return privateKey; }
    public String getSignatureProviderName() { return signatureProviderName; }
    public OcspKeyBinding getOcspKeyBinding() { return ocspKeyBinding; }
    public int getResponderIdType() { return responderIdType; }
    public RespID getRespId() { return respId; }
    public X509Certificate[] getResponseCertChain() { return responseCertChain; }
    /**
     * Checks if the entry has a OCSP signing certificate separate from the certificate chain.
     * Only entries with a keybinding can have a separate certificate.
     * */
    public boolean isUsingSeparateOcspSigningCertificate() { return ocspSigningCertificate != null; }
    public boolean isSigningCertificateForOcspSigning() { return signingCertificateForOcspSigning; }
    
    public CertificateStatus getIssuerCaCertificateStatus() {
        return issuerCaCertificateStatus;
    }

    public boolean isPlaceholder() { return privateKey == null; }

    public X509Certificate getIssuerCaCertificate() {
        return issuerCaCertificate;
    }

    /** @return false for the first thread that invokes this method (a caller that gets a false return value should verify the response signature) */
    public boolean checkResponseSignatureVerified() {
        // There is a small race condition here, so multiple callers might get a "false" return value, but since this
        // is a hot-path we don't want the overhead of synchronization for a large majority of the invocations
        if (responseSignatureVerified) {
            return true;
        }
        responseSignatureVerified = true;
        return false;
    }

    /**
     * This method construct the certificate chain that will be included in the OCSP response according to the following rules:
     * - If includeSignCert && includeChain --> include entire chain except for the root CA certificate
     * - If includeSignCert && !includeChain --> include only the signing certificate whatever it is (even if it was a root CA cert)
     * - If !includingSignCert --> not including any certificate or chain no matter what value includeChain has. The value of the 
     *   certificate chain  will then be an empty array.
     *   
     * @param certChain
     * @return the certificate chain that will be included in the OCSP response
     */
    private X509Certificate[] getResponseCertChain(X509Certificate[] certChain) {
        X509Certificate[] chain;
        boolean includeSignCert = OcspConfiguration.getIncludeSignCert();
        boolean includeChain = OcspConfiguration.getIncludeCertChain();
        // If we have an OcspKeyBinding we use this configuration to override the default
        if (isUsingSeparateOcspSigningCertificate()) {
            includeSignCert = getOcspKeyBinding().getIncludeSignCert();
            includeChain = getOcspKeyBinding().getIncludeCertChain();
        }
        if(log.isDebugEnabled()) {
            log.debug("Include signing cert: " + includeSignCert);
            log.debug("Include chain: " + includeChain);
        }
        if(includeSignCert) {
            if (includeChain) {
                if(certChain.length > 1) { // certChain contained more than the root cert
                    //create a new array containing all the certs in certChain except for the root cert
                    chain = new X509Certificate[certChain.length-1];
                    for(int i=0; i<chain.length; i++) {
                        chain[i] = certChain[i];
                    }
                } else { // certChain contains only the root cert
                    chain = certChain;
                }
            } else { // only the signing cert should be included in the OCSP response and not the entire cert chain
                chain = new X509Certificate[1];
                chain[0] = certChain[0];
            }
        } else {
            if(log.isDebugEnabled()) {
                log.debug("OCSP signing certificate is not included in the response");
            }
            chain = new X509Certificate[0];
        }
        return chain;
    }
}
