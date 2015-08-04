/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.core.protocol.scep.ScepResponseMessage;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Enterprise plugin containing the SCEP Client Certificate Renewal functionality as defined in http://tools.ietf.org/html/draft-nourse-scep-23#appendix-D
 * 
 * @version $Id$
 *
 */
public class ClientCertificateRenewalExtension implements ScepResponsePlugin {

    private static final Logger log = Logger.getLogger(ClientCertificateRenewalExtension.class);
    
    private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
  
    /*
     * Will attempt a Client Certificate Renewal operation, but will default to a standard enrollment attempt if the End Entity in question
     * doesn't have status GENERATED 
     * 
     */
    @Override
    public ResponseMessage performOperation(AuthenticationToken authenticationToken, ScepRequestMessage reqmsg, ScepConfiguration scepConfig,
            String scepAlias) throws NoSuchEndEntityException, CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException,
            IllegalKeyException, SignatureException, CustomCertificateSerialNumberException, SignRequestException, SignRequestSignatureException,
            AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException,
            ClientCertificateRenewalException {

        final CertificateStoreSessionLocal certificateStoreSession = ejbLocalHelper.getCertificateStoreSession();
        final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = ejbLocalHelper.getCryptoTokenManagementSession();
        final EndEntityAccessSessionLocal endEntityAccessSession = ejbLocalHelper.getEndEntityAccessSession();
        final SignSessionLocal signSession = ejbLocalHelper.getSignSession();

        //Investigate if this could be a Client Certificate Renewal request  
        CA ca = signSession.getCAFromRequest(authenticationToken, reqmsg, false);
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        final Certificate rolloverCACert = (ca.getRolloverCertificateChain() != null ? ca.getRolloverCertificateChain().iterator().next() : null);
        final String keyAlias;
        final Certificate cacert;
        final boolean useRolloverCert;
        if (ca.getUseNextCACert(reqmsg)) {
            keyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
            cacert = rolloverCACert;
            useRolloverCert = true;
        } else {
            keyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            cacert = ca.getCACertificate();
            useRolloverCert = false;
        }
        
        //Initialize request message to get the username.      
        reqmsg.setKeyInfo(cacert, cryptoToken.getPrivateKey(keyAlias), cryptoToken.getSignProviderName());
        reqmsg.verify();
        final String username = reqmsg.getUsername();
        if (username == null) {
            throw new IllegalArgumentException("Request was sent with null username.");
        }
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, username);
        if (endEntityInformation == null) {
            throw new NoSuchEndEntityException("End entity with username " + username + " does not exist.");
        }
        
        // Find latest issued certificate
        final X509Certificate latestIssued;
        if (useRolloverCert) {
            X509Certificate rolloverCert = certificateStoreSession.findLatestX509CertificateBySubject(reqmsg.getRequestDN(), cacert, true);
            if (rolloverCert != null) {
                throw new IllegalStateException("Can't issue more than one rollover certificate.");
            }
            latestIssued = certificateStoreSession.findLatestX509CertificateBySubject(reqmsg.getRequestDN(), cacert, false);
            if (latestIssued == null) {
                throw new IllegalStateException("End entity with username " + endEntityInformation.getUsername() + " has a rollover certiticate, but no valid certificate was found.");
            }
            log.debug("Found existing certificate, will use client certificate renewal for rollover certificate");
        } else if (endEntityInformation.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            latestIssued = certificateStoreSession.findLatestX509CertificateBySubject(reqmsg.getRequestDN(), cacert, false);
            if (latestIssued == null) {
                throw new IllegalStateException("End entity with username " + endEntityInformation.getUsername() + " has status generated, but no certificate was found.");
            }
            log.debug("Found existing certificate, will use client certificate renewal");
        } else {
            log.debug("No existing certificate exists. Performing normal enrolment with password authentication");
            return signSession.createCertificate(authenticationToken, reqmsg, ScepResponseMessage.class, null);
        }
        
        // Verify that certificate is still valid
        if(!CertTools.isCertificateValid(latestIssued)) {
            throw new AuthStatusException("Re-enrollment request was attempted using an expired client certificate");
        }
        
        // Double check that certificate hasn't been revoked
        final CertificateStatus certStatus = certificateStoreSession.getStatus(CertTools.getIssuerDN(latestIssued), latestIssued.getSerialNumber());
        if (!certStatus.equals(CertificateStatus.OK)) {
            throw new AuthStatusException("Certificate status for end entity with username " + username + " is "+certStatus);
        }
        
        long expirationTime = latestIssued.getNotAfter().getTime();
        long issueTime = latestIssued.getNotBefore().getTime();
        /* 
         * If client certificate renewal is allowed, we will interpret an enrollment request as a renewal, given that the existing 
         * certificate has passed half its validity. 
         * 
         * See draft-nourse-scep-23 Appendix D
         */
        if (System.currentTimeMillis() <= (issueTime + (expirationTime - issueTime) / 2)) {
            throw new ClientCertificateRenewalException("Re-enrollment request was sent but last issued certificate for username " + username
                    + " hasn't passed half its validity date yet.");
        }
        
        // A new keypair may (but should) be used by the client. This can be enforced by the server. 
        if (!scepConfig.getAllowClientCertificateRenewalWithOldKey(scepAlias)) {
            if (reqmsg.getRequestPublicKey().equals(latestIssued.getPublicKey())) {
                throw new IllegalKeyException("Configuration prohibits certificate renewal reusing old keys, for username '" + username
                        + "' and SCEP configuration alias '" + scepAlias + "'");
            }
        }
        //The request must be signed by the existing client certificate's private key
        try {
            if (!reqmsg.verifySignature(latestIssued.getPublicKey())) {
                throw new SignatureException(
                        "Client Certificate Renewal request should have been signed by the old certificate's private key.");
            }
        } catch (CMSException e) {
            throw new SignatureException("Could not process PKCS#7 signature in SCEP message.", e);
        } catch (OperatorCreationException e) {
            throw new SignatureException("Public key retrieved from database certificate apparently not valid.", e);
        }
        // This has to be done within a transaction, as setting status to NEW first and then attempting to generate a certificate
        // may lead to end entity being left with the NEW status
        // Get the certificate 
        try {
            // The SCEP draft left challenge password in renewal as a MAY:
            // "A client that is performing certificate renewal as per Appendix D SHOULD send an empty challenge password 
            // (i.e. use the empty string as the challenge password) but MAY send the originally distributed challenge password 
            // in the challengePassword attribute. In the former case the SCEP CA MUST authenticate the request based on the 
            // certificate used to sign the renewal request. In the latter case the SCEP CA MAY use either the challengePassword 
            // or the previously issued certificate (or both) to authenticate the request."
            boolean ignorePassword = StringUtils.isEmpty(reqmsg.getPassword());
            if (ignorePassword) {
                reqmsg.setPassword(PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS)
                        .getNewPassword(12, 12));
            }
            return signSession.createCertificateIgnoreStatus(authenticationToken, reqmsg, ScepResponseMessage.class, ignorePassword);
        } catch (ApprovalException e) {
            throw new ClientCertificateRenewalException(e);
        } catch (WaitingForApprovalException e) {
            throw new ClientCertificateRenewalException(e);
        }
    }

}
