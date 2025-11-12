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
package org.ejbca.core.protocol.scep;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSession;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenManagementSession;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

import java.security.cert.X509Certificate;

/**
 * I generate certificates to encrypt/sign SCEP messages.
 */
public class ScepRaCertificateIssuer {

    private CryptoTokenManagementSession cryptoTokenManagementSession;
    private CaSession caSession;
    private EndEntityManagementSession endEntityManagementSession;
    private CertificateCreateSession certificateCreateSession;

    public ScepRaCertificateIssuer(CryptoTokenManagementSession cryptoTokenManagementSession, CaSession caSession,
            EndEntityManagementSession endEntityManagementSession, CertificateCreateSession certificateCreateSession) {
        this.cryptoTokenManagementSession = cryptoTokenManagementSession;
        this.caSession = caSession;
        this.endEntityManagementSession = endEntityManagementSession;
        this.certificateCreateSession = certificateCreateSession;
    }

    public X509Certificate issueEncryptionCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias) throws ScepEncryptionCertificateIssuanceException {
        return issueCertificate(authenticationToken, caName, cryptoTokenId, keyAlias, CertificateProfileConstants.CERTPROFILE_FIXED_SCEP_ENCRYPTOR);
    }

    public X509Certificate issueSigningCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias) throws ScepEncryptionCertificateIssuanceException {
        return issueCertificate(authenticationToken, caName, cryptoTokenId, keyAlias, CertificateProfileConstants.CERTPROFILE_FIXED_SCEP_SIGNER);
    }

    private X509Certificate issueCertificate(AuthenticationToken authenticationToken, String caName, int cryptoTokenId,
            String keyAlias, int fixedCertificateProfileId) throws ScepEncryptionCertificateIssuanceException {
        CertificateResponseMessage certificateResponse;
        try {
            var publicKeyWrapper = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, keyAlias);

            int caId = caSession.getCAInfo(authenticationToken, caName).getCAId();
            String userName = "SCEP_RA_" + caId;
            String dn = "CN=" + userName;

            String password = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE).getNewPassword(14, 16);

            var endEntityInformation = new EndEntityInformation();
            endEntityInformation.setUsername(userName);
            endEntityInformation.setPassword(password);
            endEntityInformation.setDN(dn);
            endEntityInformation.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            endEntityInformation.setCertificateProfileId(fixedCertificateProfileId);
            endEntityInformation.setType(new EndEntityType(EndEntityTypes.ENDUSER));
            endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
            endEntityInformation.setCAId(caId);

            var requestMessage = new SimpleRequestMessage(publicKeyWrapper.getPublicKey(), userName, password);
            certificateResponse = certificateCreateSession.createCertificate(authenticationToken, endEntityInformation, requestMessage,
                    X509ResponseMessage.class, new CertificateGenerationParams());
            return (X509Certificate) certificateResponse.getCertificate();
        } catch (CryptoTokenOfflineException | CADoesntExistsException | IllegalNameException
                | CertificateSerialNumberException | CustomCertificateSerialNumberException | IllegalKeyException
                | CertificateCreateException | SignRequestSignatureException | CertificateRevokeException | IllegalValidityException
                | CAOfflineException | InvalidAlgorithmException | AuthorizationDeniedException
                | CertificateExtensionException e) {
            throw new ScepEncryptionCertificateIssuanceException(e);
        }
    }

}
