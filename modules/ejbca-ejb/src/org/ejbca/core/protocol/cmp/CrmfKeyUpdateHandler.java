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

package org.ejbca.core.protocol.cmp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSession;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.cmp.authentication.EndEntityCertificateAuthenticationModule;

/**
 * Message handler for update messages using the CRMF format for the request itself.
 * 
 * @version $Id$
 */
public class CrmfKeyUpdateHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
    
    private static final Logger LOG = Logger.getLogger(CrmfKeyUpdateHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    /** strings for error messages defined in internal resources */
    private static final String CMP_ERRORGENERAL = "cmp.errorgeneral";

    private final AuthorizationSession authorizationSession;
    private final CertificateStoreSession certStoreSession;
    private final EndEntityAccessSession endEntityAccessSession;
    private final EndEntityManagementSession endEntityManagementSession;
    private final SignSession signSession;
    private final WebAuthenticationProviderSessionLocal authenticationProviderSession;


    public CrmfKeyUpdateHandler(AuthenticationToken authenticationToken, String configAlias, EjbBridgeSessionLocal ejbBridgeSession) {
        super(authenticationToken, configAlias, ejbBridgeSession);
        this.signSession = ejbBridgeSession.getSignSession();
        this.endEntityAccessSession = ejbBridgeSession.getEndEntityAccessSession();
        this.certStoreSession = ejbBridgeSession.getCertificateStoreSession();
        this.authorizationSession = ejbBridgeSession.getAuthorizationSession();
        this.authenticationProviderSession = ejbBridgeSession.getWebAuthenticationProviderSession();
        this.endEntityManagementSession = ejbBridgeSession.getEndEntityManagementSession();
    }

    @Override
    /*
     * Handles the CMP message
     * 
     * Expects the CMP message to be a CrmfRequestMessage. The message is authenticated using 
     * EndEntityCertificateAuthenticationModule in client mode. It used the attached certificate 
     * to find then End Entity which this certificate belongs to and requesting for a new certificate 
     * to be generated. 
     * 
     * If automatic update of the key (same as certificate renewal), the end entity's status is set to 
     * 'NEW' before processing the request. If using the same old keys in the new certificate is not allowed, 
     * a check is made to insure the the key specified in the request is not the same as the key of the attached 
     * certificate.
     * 
     * The KeyUpdateRequet is processed only in client mode.
     */
    public ResponseMessage handleMessage(final BaseCmpMessage msg, boolean authenticated) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">handleMessage");
        }
        
        
        // NOTE. If we will issue the new certificate using another CertificateProfile and/or CA than the ones specified 
        // in the end entity (prior to receiving the request), update the authorization check in 
        // EndEntityCertificateAuthenticationModule.isAuthorizedAdmin() to check authorization to the right CertProfile and CA 
        
        if(LOG.isDebugEnabled()) {
            LOG.debug("CMP running on RA mode: " + this.cmpConfiguration.getRAMode(this.confAlias));
        }

        ResponseMessage resp = null;
        try {

            CrmfRequestMessage crmfreq = null;
            if (msg instanceof CrmfRequestMessage) {
                crmfreq = (CrmfRequestMessage) msg;
                crmfreq.getMessage();

                EndEntityCertificateAuthenticationModule eecmodule = null;
                X509Certificate oldCert = null;
                        
                // Find the subjectDN to look for
                String subjectDN = null;
                String issuerDN = null;
                if(this.cmpConfiguration.getRAMode(this.confAlias)) {                    
                    // Check that EndEntityCertificate authentication module is set
                    if(!cmpConfiguration.isInAuthModule(confAlias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
                        String errmsg = "EndEntityCertificate authentication module is not configured. For a KeyUpdate request to be authentication in RA mode, EndEntityCertificate " +
                        		"authentication module has to be set and configured";
                        LOG.info(errmsg);
                        return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, errmsg);
                    }
                    // Check PKIMessage authentication
                    String authparameter = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, confAlias);
                    eecmodule = new EndEntityCertificateAuthenticationModule(admin, authparameter, 
                            confAlias, cmpConfiguration, authenticated, caSession, certStoreSession, authorizationSession, endEntityProfileSession, certificateProfileSession,
                            endEntityAccessSession, authenticationProviderSession, endEntityManagementSession);
                    if(!eecmodule.verifyOrExtract(crmfreq.getPKIMessage(), null)) {
                        LOG.info(eecmodule.getErrorMessage());
                        return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, eecmodule.getErrorMessage());
                    } else {
                        if(LOG.isDebugEnabled()) {
                            LOG.debug("The CMP KeyUpdate request for SubjectDN '" + crmfreq.getSubjectDN() +"' was verified successfully");
                        }
                    }
                    oldCert = (X509Certificate) certStoreSession.findLatestX509CertificateBySubject(crmfreq.getSubjectDN());
                    
                    CertReqMessages kur = (CertReqMessages) crmfreq.getPKIMessage().getBody().getContent();
                    CertReqMsg certmsg;
                    try {
                        certmsg = kur.toCertReqMsgArray()[0];
                    } catch(Exception e) {
                        LOG.debug("Could not parse the revocation request. Trying to parse it as novosec generated message.");
                        certmsg = CmpMessageHelper.getNovosecCertReqMsg(kur);
                        LOG.debug("Succeeded in parsing the novosec generated request.");
                    }
                    X500Name dn = certmsg.getCertReq().getCertTemplate().getSubject();
                    if(dn != null) {
                        subjectDN = dn.toString();
                    }
                    dn = certmsg.getCertReq().getCertTemplate().getIssuer();
                    if(dn != null) {
                        issuerDN = dn.toString();
                    }
                } else { // client mode
                    
                    eecmodule = new EndEntityCertificateAuthenticationModule(admin, null, 
                            confAlias, cmpConfiguration, authenticated, caSession, certStoreSession, authorizationSession, endEntityProfileSession, certificateProfileSession, 
                            endEntityAccessSession, authenticationProviderSession, endEntityManagementSession);
                    if(!eecmodule.verifyOrExtract(crmfreq.getPKIMessage(), null)) {
                        LOG.info(eecmodule.getErrorMessage());
                        return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, eecmodule.getErrorMessage());
                    }
                    oldCert = (X509Certificate) eecmodule.getExtraCert();
                    
                    subjectDN = oldCert.getSubjectDN().toString(); 
                    issuerDN = oldCert.getIssuerDN().toString();
                }

                if(subjectDN == null) {
                    final String errMsg = "Cannot find a SubjectDN in the request";
                    LOG.info(errMsg);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, errMsg);
                }
                
                // Find the end entity that the certificate belongs to                
                if(LOG.isDebugEnabled()) {
                    LOG.debug("Looking for an end entity with subjectDN: " + subjectDN);
                }
                EndEntityInformation endEntityInformation = null;
                if(issuerDN == null) {
                    if(LOG.isDebugEnabled()) {
                        LOG.debug("The CMP KeyUpdateRequest did not specify an issuer");
                    }
                    List<EndEntityInformation> userdataList = endEntityAccessSession.findUserBySubjectDN(admin, subjectDN);
                    if (userdataList.size() > 0) {
                        endEntityInformation = userdataList.get(0);
                    }
                    if (userdataList.size() > 1) {
                        LOG.warn("Multiple end entities with subject DN " + subjectDN + " were found. This may lead to unexpected behavior.");
                    }
                } else {
                    List<EndEntityInformation> userdataList = endEntityAccessSession.findUserBySubjectAndIssuerDN(admin, subjectDN, issuerDN);
                    if (userdataList.size() > 0) {
                        endEntityInformation = userdataList.get(0);
                    }
                    if (userdataList.size() > 1) {
                        LOG.warn("Multiple end entities with subject DN " + subjectDN + " and issuer DN" + issuerDN
                                + " were found. This may lead to unexpected behavior.");
                    }
                }

                if(endEntityInformation == null) {
                    final String errMsg = INTRES.getLocalizedMessage("cmp.infonouserfordn", subjectDN);
                    LOG.info(errMsg);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                }
                
                if(LOG.isDebugEnabled()) {
                    LOG.debug("Found user '" + endEntityInformation.getUsername() + "'");
                }
            
                /*
                 * Check the status of the certificate that should be updated.
                 * 
                 * RFC4210 states in ch. 5.3.5:
                 * "[...] This message is intended to be used to request updates to existing (non-revoked and non-expired) certificates [...]" 
                 */
                if(certStoreSession.isRevoked(CertTools.getIssuerDN(oldCert), CertTools.getSerialNumber(oldCert))) {
                    String errorMessage = "Certificate for end entity with username " + endEntityInformation.getUsername() + " with subject DN " + subjectDN
                            + " is revoked. Unable to perform key update.";
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(errorMessage);
                    }
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, errorMessage);
                }
                try {
                    oldCert.checkValidity();
                } catch (CertificateExpiredException e) {
                    String errorMessage = "Certificate for end entity with username " + endEntityInformation.getUsername() + " with subject DN "
                            + subjectDN + " is expired. Unable to perform key update.";
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(errorMessage);
                    }
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, errorMessage);
                } catch(CertificateNotYetValidException e) {
                    //A not yet valid certificate is still valid for update according to the RFC. 
                }
                        
                // The password that should be used to obtain the new certificate
                String password = StringUtils.isNotEmpty(endEntityInformation.getPassword()) ? endEntityInformation.getPassword() : eecmodule.getAuthenticationString();
                
                // Set the appropriate parameters in the end entity
                endEntityInformation.setPassword(password);
                endEntityManagementSession.changeUser(admin, endEntityInformation, false);
                if(this.cmpConfiguration.getKurAllowAutomaticUpdate(this.confAlias)) {
                    if(LOG.isDebugEnabled()) {
                        LOG.debug("Setting the end entity status to 'NEW'. Username: " + endEntityInformation.getUsername());
                    }    
                    endEntityManagementSession.setUserStatus(admin, endEntityInformation.getUsername(), EndEntityConstants.STATUS_NEW);
                }
                
                // Set the appropriate parameters in the request
                crmfreq.setUsername(endEntityInformation.getUsername());
                crmfreq.setPassword(password);
                if(crmfreq.getHeader().getProtectionAlg() != null) {
                    crmfreq.setPreferredDigestAlg(AlgorithmTools.getDigestFromSigAlg(crmfreq.getHeader().getProtectionAlg().getAlgorithm().getId()));
                }

                // Check the public key, whether it is allowed to use the old keys or not.
                if(!this.cmpConfiguration.getKurAllowSameKey(this.confAlias)) {
                    PublicKey certPublicKey = oldCert.getPublicKey();
                    PublicKey requestPublicKey = crmfreq.getRequestPublicKey();
                    if(LOG.isDebugEnabled()) {
                        LOG.debug("Not allowing update with same key, comparing keys.");
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("OldKey: "+certPublicKey.toString());
                            LOG.trace("NewKey: "+requestPublicKey.toString());
                        }
                    }
                    if(certPublicKey.equals(requestPublicKey)) {
                        final String errMsg = "Invalid key. The public key in the KeyUpdateRequest is the same as the public key in the existing end entity certificate";
                        LOG.info(errMsg);
                        return CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                    }
                }

                // Process the request
                resp = signSession.createCertificate(admin, crmfreq, org.ejbca.core.protocol.cmp.CmpResponseMessage.class, endEntityInformation);               

                if (resp == null) {
                    final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
                    LOG.info(errMsg);
                    resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                }
            } else {
                final String errMsg = INTRES.getLocalizedMessage("cmp.errornocmrfreq");
                LOG.info(errMsg);
                resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_MESSAGE_CHECK, errMsg);
            }

        } catch (AuthorizationDeniedException | CADoesntExistsException | EndEntityProfileValidationException | InvalidAlgorithmException | CAOfflineException | IllegalValidityException | CertificateSerialNumberException
                |  CustomCertificateSerialNumberException | CryptoTokenOfflineException | IllegalKeyException
                | SignRequestException | SignRequestSignatureException | IllegalNameException | CertificateCreateException
                | CertificateRevokeException | NoSuchEndEntityException | EjbcaException | CertificateExtensionException | WaitingForApprovalException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (InvalidKeyException | NoSuchProviderException | NoSuchAlgorithmException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info("Error while reading the public key of the extraCert attached to the CMP request");
            LOG.info(errMsg, e);
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, FailInfo.BAD_REQUEST, e.getMessage());
        }

        if (LOG.isTraceEnabled()) {
            LOG.trace("<handleMessage");
        }
        return resp;
    }
   
}
