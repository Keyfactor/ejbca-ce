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
package org.cesecore.certificate.ca.its;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.operator.ITSContentSigner;

import org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicVerificationKey;
import org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate.Builder;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

public interface ECA extends CA {
    
    static final String CA_TYPE = "ECA";
    
    /**
     * TODO document parameters once they're determined.
     * Generate explicit EtsiTs103097Certificate intended for C-ITS application.
     * 
     * @param cryptoToken
     * @param subject
     * @param request
     * @param publicKey
     * @param keyusage
     * @param notBefore
     * @param notAfter
     * @param certProfile
     * @param extensions
     * @param sequence
     * @param certGenParams
     * @param cceConfig
     * @return
     * @throws CryptoTokenOfflineException
     * @throws CAOfflineException
     * @throws InvalidAlgorithmException
     * @throws IllegalValidityException
     * @throws IllegalNameException
     * @throws OperatorCreationException
     * @throws CertificateCreateException
     * @throws CertificateExtensionException
     * @throws SignatureException
     * @throws IllegalKeyException
     */
    ITSCertificate generateExplicitItsCertificate(CryptoToken cryptoToken, EndEntityInformation subject, PublicVerificationKey publicKey,
        Date notBefore, Date notAfter, CertificateProfile certProfile, Builder certificateBuilder, CertificateId certifcateId, String sequence)
        throws CryptoTokenOfflineException;
    
    
    /**
     * TODO document parameters once they're determined.
     * Generate implicit EtsiTs103097Certificate intended for C-ITS application.
     * 
     * @param subject
     * @param request
     * @param publicKey
     * @param keyusage
     * @param notBefore
     * @param notAfter
     * @param certProfile
     * @param extensions
     * @param sequence
     * @param certGenParams
     * @param cceConfig
     * @return
     * @throws CryptoTokenOfflineException
     * @throws CAOfflineException
     * @throws InvalidAlgorithmException
     * @throws IllegalValidityException
     * @throws IllegalNameException
     * @throws OperatorCreationException
     * @throws CertificateCreateException
     * @throws CertificateExtensionException
     * @throws SignatureException
     * @throws IllegalKeyException
     */
    ITSCertificate generateImplicitItsCertificate(EndEntityInformation subject, RequestMessage request, PublicKey publicKey, int keyusage,
            Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException;
    
    void setItsCaCertificate(final ITSCertificate caCertificate);
        
    ITSCertificate getItsCACertificate();
    
    byte[] createRequest(final CryptoToken cryptoToken, final String signKeyAlias, 
            final String verificationKeyAlias, final String encryptKeyAlias,
             final CertificateProfile certificateProfile) throws CryptoTokenOfflineException, CertificateExtensionException;


    void setCertificateHash(String hexString);

    String getCertificateHash();
    
    ITSContentSigner getITSContentSigner(PrivateKey privateKey, ITSCertificate signerCert) throws IllegalKeyException;
}
