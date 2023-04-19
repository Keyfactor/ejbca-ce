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
package org.ejbca.ra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.faces.validator.ValidatorException;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.roles.management.RoleSessionLocal;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;

/**
 * Managed bean that backs up the enrollwithrequestid.xhtml page
 */
@Named
@ViewScoped
public class EnrollWithRequestIdBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollWithRequestIdBean.class);

    protected String requestId;
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private RoleSessionLocal roleSession;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;

    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    @Inject
    protected RaLocaleBean raLocaleBean;

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    private CertificateProfile certificateProfile;
    private String requestUsername;
    private String selectedAlgorithm;
    private String certificateRequest;
    private int requestStatus;
    private EndEntityInformation endEntityInformation;
    private byte[] generatedToken;
    private IdNameHashMap<CAInfo> authorizedCAInfos;
    protected IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
    private boolean isCsrChanged;
    private boolean isKeyRecovery;
    private boolean statusAllowsEnrollment;
    private boolean deletePublicAccessRole = true;
    private boolean deletePublicAccessRoleRendered;

    @PostConstruct
    protected void postConstruct() {
        HttpServletRequest httpServletRequest = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        this.authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken(), AccessRulesConstants.CREATE_END_ENTITY);
        requestId = httpServletRequest.getParameter(EnrollMakeNewRequestBean.PARAM_REQUESTID);
        this.authorizedCAInfos = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
        reset();
    }

    public void reset() {
        requestStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        endEntityInformation = null;
        selectedAlgorithm = null;
        certificateProfile = null;
        generatedToken = null;
    }

    /** Check the status of request ID */
    public void checkRequestId() {
        if (Integer.parseInt(requestId) != 0) {
            RaApprovalRequestInfo raApprovalRequestInfo = raMasterApiProxyBean
                    .getApprovalRequest(raAuthenticationBean.getAuthenticationToken(), Integer.parseInt(requestId));
            if (raApprovalRequestInfo == null) {
                raLocaleBean.addMessageError("enrollwithrequestid_could_not_find_request_with_request_id", Integer.parseInt(requestId));
                return;
            }

            requestStatus = raApprovalRequestInfo.getStatus();
            switch (requestStatus) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_is_still_waiting_for_approval", Integer.parseInt(requestId));
                break;
            case ApprovalDataVO.STATUS_REJECTED:
            case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_rejected", Integer.parseInt(requestId));
                break;
            case ApprovalDataVO.STATUS_APPROVED:
            case ApprovalDataVO.STATUS_EXECUTED:
                ApprovalRequest approvalRequest = raApprovalRequestInfo.getApprovalData().getApprovalRequest();
                if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
                    KeyRecoveryApprovalRequest keyRecoveryApprovalRequest = (KeyRecoveryApprovalRequest) approvalRequest;
                    requestUsername = keyRecoveryApprovalRequest.getUsername();
                    isKeyRecovery = true;
                } else {
                    requestUsername = raApprovalRequestInfo.getEditableData().getUsername();
                }
                final EndEntityInformation eei = raMasterApiProxyBean.searchUserWithoutViewEndEntityAccessRule(raAuthenticationBean.getAuthenticationToken(), requestUsername);
                if (eei == null) {
                    log.error("Could not find endEntity for the username='" + requestUsername + "'");
                } else if (eei.getStatus() == EndEntityConstants.STATUS_GENERATED) {
                    raLocaleBean.addMessageInfo("enrollwithrequestid_enrollment_with_request_id_has_already_been_finalized", Integer.parseInt(requestId));
                } else {
                    raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_approved", Integer.parseInt(requestId));
                }
                setEndEntityInformation(eei);
                break;
            case ApprovalDataVO.STATUS_EXPIRED:
            case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_expired", Integer.parseInt(requestId));
                break;
            case ApprovalDataVO.STATUS_EXECUTIONFAILED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_could_not_be_executed", Integer.parseInt(requestId));
                break;
            default:
                raLocaleBean.addMessageError("enrollwithrequestid_status_of_request_id_is_unknown", Integer.parseInt(requestId));
                break;
            }
        }
    }

    public boolean isFinalizeEnrollmentRendered() {
        return (requestStatus == ApprovalDataVO.STATUS_APPROVED || requestStatus == ApprovalDataVO.STATUS_EXECUTED) &&
                statusAllowsEnrollment;
    }

    public void generateCertificatePem() {
        generateCertificate();
        if (generatedToken != null) {
            try {
                Certificate certificate = CertTools.getCertfromByteArray(generatedToken, Certificate.class);
                byte[] pemToDownload = CertTools.getPemFromCertificateChain(List.of(certificate));
                downloadToken(pemToDownload, "application/octet-stream", ".pem");
            } catch (CertificateParsingException | CertificateEncodingException e) {
                log.info(e);
            }
        } else {
            log.debug("No token was generated an error message should have been logged");
        }
        reset();
    }

    public void generateCertificatePemFullChain() {
        generateCertificate();
        if (generatedToken != null) {
            try {
                Certificate certificate = CertTools.getCertfromByteArray(generatedToken, Certificate.class);
                CAInfo caInfo = authorizedCAInfos.get(endEntityInformation.getCAId()).getValue();
                LinkedList<Certificate> chain = new LinkedList<>(caInfo.getCertificateChain());
                chain.addFirst(certificate);
                byte[] pemToDownload = CertTools.getPemFromCertificateChain(chain);
                downloadToken(pemToDownload, "application/octet-stream", ".pem");
            } catch (CertificateParsingException | CertificateEncodingException e) {
                log.info(e);
            }
        } else {
            log.debug("No token was generated an error message should have been logged");
        }
        reset();
    }

    public void generateCertificateDer() {
        generateCertificate();
        downloadToken(generatedToken, "application/octet-stream", ".der");
        reset();
    }

    public void generateCertificatePkcs7() {
        generateCertificate();
        if (generatedToken != null) {
            try {
                X509Certificate certificate = CertTools.getCertfromByteArray(generatedToken, X509Certificate.class);
                CAInfo caInfo = authorizedCAInfos.get(endEntityInformation.getCAId()).getValue();
                LinkedList<Certificate> chain = new LinkedList<>(caInfo.getCertificateChain());
                chain.addFirst(certificate);
                byte[] pkcs7ToDownload = CertTools.getPemFromPkcs7(CertTools.createCertsOnlyCMS(CertTools.convertCertificateChainToX509Chain(chain)));
                downloadToken(pkcs7ToDownload, "application/octet-stream", ".p7b");
            } catch (CertificateParsingException | CertificateEncodingException | ClassCastException | CMSException e) {
                log.info(e);
            }
        } else {
            log.debug("No token was generated an error message should have been logged");
        }
        reset();
    }

    protected final void generateCertificateAfterCheck(){
        try {
            generatedToken = raMasterApiProxyBean.createCertificate(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
            log.info("Token (type " + endEntityInformation.getTokenType() + ") has been generated for the end entity with username " +
                    endEntityInformation.getUsername());
        } catch (AuthorizationDeniedException e){
            raLocaleBean.addMessageInfo("enroll_unauthorized_operation", e.getMessage());
            log.info(raAuthenticationBean.getAuthenticationToken() + " is not authorized to execute this operation", e);
        } catch (EjbcaException e) {
            ErrorCode errorCode = EjbcaException.getErrorCode(e);
            if (errorCode != null) {
                if (errorCode.equals(ErrorCode.LOGIN_ERROR)) {
                    raLocaleBean.addMessageError("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), errorCode);
                    log.info("Keystore could not be generated for user " + endEntityInformation.getUsername()+": "+e.getMessage()+", "+errorCode);
                } else {
                    raLocaleBean.addMessageError(errorCode);
                    log.info("Exception generating certificate. Error Code: " + errorCode, e);
                }
            } else {
                raLocaleBean.addMessageError("enroll_certificate_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage());
                log.info("Certificate could not be generated for end entity with username " + endEntityInformation.getUsername(), e);
            }
        }
    }

    protected void generateCertificate() {
        if (getEndEntityInformation().getExtendedInformation() == null) {
            getEndEntityInformation().setExtendedInformation(new ExtendedInformation());
        }
        byte[] certificateRequest = getEndEntityInformation().getExtendedInformation().getCertificateRequest();
        if (certificateRequest == null || isCsrChanged) {
            if (getCertificateRequest() == null) {
                raLocaleBean.addMessageError("enrollwithrequestid_could_not_find_csr_inside_enrollment_request_with_request_id", requestId);
                log.info("Could not find CSR inside enrollment request with ID " + requestId);
                return;
            }
            byte[] binaryReqBytes = RequestMessageUtils.getDecodedBytes(getCertificateRequest().getBytes());
            RequestMessage reqMsg = RequestMessageUtils.parseRequestMessage(binaryReqBytes);
            if (reqMsg == null) {
                // Just make an extra check that it's a valid request
                raLocaleBean.addMessageError("enroll_invalid_certificate_request");
                return;
            }
            getEndEntityInformation().getExtendedInformation().setCertificateRequest(binaryReqBytes);
        }
        generateCertificateAfterCheck();
        if (generatedToken != null && isDeletePublicAccessRoleRendered() && isDeletePublicAccessRole()) {
            try {
                final AlwaysAllowLocalAuthenticationToken adminToken = new AlwaysAllowLocalAuthenticationToken("DeleteRoleAfterSuperadminEnrollment");
                roleSession.deleteRoleIdempotent(adminToken, null, AuthorizationSystemSession.PUBLIC_ACCESS_ROLE);
            } catch (AuthorizationDeniedException e) {
                raLocaleBean.addMessageError("enrolle_failed_delete_role");
                log.error("Not authorized to create CA: " + e.getMessage());
            }
        }
    }

    public void generateKeyStoreJks() {
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_JKS);
        generateKeyStore();
        downloadToken(generatedToken, "application/octet-stream", ".jks");
        reset();
    }

    public void generateKeyStorePkcs12() {
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
        generateKeyStore();
        downloadToken(generatedToken, "application/x-pkcs12", ".p12");
        if (requestId == null) {
            reset();
        }
    }

    public void generateKeyStoreBcfks() {
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_BCFKS);
        generateKeyStore();
        downloadToken(generatedToken, "application/x-pkcs12", ".p12");
        reset();
    }

    public void generateKeyStorePem() {
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_PEM);
        generateKeyStore();
        downloadToken(generatedToken, "application/octet-stream", ".pem");
        reset();
    }

    /**
     * Updates the end entity, if the key specification selected by the user differs 
     * from the end entities last key specification used. If successful, the key pair is generated.
     */
    protected void generateKeyStore() {
    	// We use the variable to tunnel the user input.
        if (log.isDebugEnabled()) {
            log.debug("Selected key algorithm by user: " + getPreSetKeyAlgorithm());
        }
        final AuthenticationToken admin = raAuthenticationBean.getAuthenticationToken();
        if (isKeyRecovery) {
            try {
                raMasterApiProxyBean.checkUserStatus(admin, endEntityInformation.getUsername(), endEntityInformation.getPassword());
            } catch (NoSuchEndEntityException | AuthStatusException | AuthLoginException e) {
                raLocaleBean.addMessageError("enrollwithusername_user_not_found_or_wrongstatus_or_invalid_enrollmentcode", endEntityInformation.getUsername());
                return;
            }
        }
        // If key algorithm is missing from EEI, we need to fetch it from CSR / select list first
        if (!isKeyAlgorithmPreSet()) {
            if (StringUtils.isEmpty(selectedAlgorithm)) {
                raLocaleBean.addMessageError("enroll_no_key_algorithm");
                log.info("No key algorithm was provided.");
                return;
            }
            final String[] parts = StringUtils.split(selectedAlgorithm, '_');
            if (parts == null || parts.length < 1) {
                raLocaleBean.addMessageError("enroll_no_key_algorithm");
                log.info("No full key algorithm was provided: "+selectedAlgorithm);
                return;
            }
            final String keyAlg = parts[0];
            if (StringUtils.isEmpty(keyAlg)) {
                raLocaleBean.addMessageError("enroll_no_key_algorithm");
                log.info("No key algorithm was provided: "+selectedAlgorithm);
                return;
            }
            final String keySpec;
            if (parts.length > 1) { // It's ok for some algs (EdDSA) to have no keySpec
                keySpec = parts[1];
                if (StringUtils.isEmpty(keySpec)) {
                    raLocaleBean.addMessageError("enroll_no_key_specification");
                    log.info("No key specification was provided: "+selectedAlgorithm);
                    return;
                }
            } else {
                keySpec = null;
            }
            if (getEndEntityInformation().getExtendedInformation() == null) {
                getEndEntityInformation().setExtendedInformation(new ExtendedInformation());
            }
            getEndEntityInformation().getExtendedInformation().setKeyStoreAlgorithmType(keyAlg);
            getEndEntityInformation().getExtendedInformation().setKeyStoreAlgorithmSubType(keySpec);
        }
        
        // Update EE information, if the key specification has changed. This might require an approval.
        if (setPreSetKeyAlgorithm(getEndEntityInformation(), getSelectedAlgorithm())) {
            try {
                raMasterApiProxyBean.editUser(admin, endEntityInformation, false, null);
                log.info("Updated end entity '" + getEndEntityInformation().getUsername() + "' key specification to '" + getSelectedAlgorithm() + "' due to manual certificate enrollment in RA mode.");
            } catch (CADoesntExistsException e1) {
                raLocaleBean.addMessageInfo("enroll_ca_not_found", e1.getMessage());
                log.info("CA with ID '" + endEntityInformation.getCAId() + "' could not be found.", e1);
                return;
            } catch (ApprovalException e1) {
                // Should not be thrown here.
                // Usually thrown, if an approval request with this ID already exists (i.e. system tries to create a second one with same properties -> same ID).
                throw new IllegalStateException(e1);
            } catch (CertificateSerialNumberException e1) {
                // Should not be thrown here (there is no certificate created).
                throw new IllegalStateException(e1);
            } catch (IllegalNameException e1) {
                // Should not be thrown here (username=null).
                throw new IllegalStateException(e1);
            } catch (NoSuchEndEntityException e1) {
                raLocaleBean.addMessageError("enroll_end_entity_not_found", e1.getMessage());
                log.info("End entity '" + endEntityInformation.getUsername() + "' could not be found.", e1);
                return;
            } catch (CustomFieldException e1) {
                // Should not be thrown here.
                throw new IllegalStateException(e1);
            } catch (AuthorizationDeniedException e1) {
                raLocaleBean.addMessageError("enroll_unauthorized_operation", e1.getMessage());
                log.info(admin + " is not authorized to execute this operation", e1);
                return;
            } catch (EndEntityProfileValidationException e1) {
                raLocaleBean.addMessageError("enroll_user_does_not_fulfill_profile", e1.getMessage());
                log.info("Could not update key specification of end entity '" + endEntityInformation.getUsername() + "'. Check certificate profile settings.", e1);
                return;
            } catch (WaitingForApprovalException e1) {
                // Thrown after the approval request was created and is waiting for approval.
                log.info("Waiting for approval of request with ID " + e1.getRequestId() + " for end entity '" + getEndEntityInformation().getUsername() + "'.");
                requestId = Integer.toString(e1.getRequestId());
                return;
            }
        }
        
        try {
            byte[] keystoreAsByteArray = raMasterApiProxyBean.generateKeyStoreWithoutViewEndEntityAccessRule(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
            log.info(endEntityInformation.getTokenType() + " token has been generated for the end entity with username " +
                    endEntityInformation.getUsername());
            try(ByteArrayOutputStream buffer = new ByteArrayOutputStream()){
                buffer.write(keystoreAsByteArray);
                generatedToken = buffer.toByteArray();
            }
        } catch (AuthorizationDeniedException e){
            raLocaleBean.addMessageInfo("enroll_unauthorized_operation", e.getMessage());
            log.info(raAuthenticationBean.getAuthenticationToken() + " is not authorized to execute this operation", e);
        } catch (EjbcaException | IOException e) {
            ErrorCode errorCode = EjbcaException.getErrorCode(e);
            if (errorCode != null) {
                if (errorCode.equals(ErrorCode.LOGIN_ERROR)) {
                    raLocaleBean.addMessageError("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), errorCode);
                    log.info("Keystore could not be generated for user " + endEntityInformation.getUsername()+": "+e.getMessage()+", "+errorCode);
                } else {
                    raLocaleBean.addMessageError(errorCode);
                    log.info("Exception generating keystore. Error Code: " + errorCode, e);
                }
            } else {
                raLocaleBean.addMessageError("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage());
                log.info("Keystore could not be generated for user " + endEntityInformation.getUsername());
            }
            return;
        } catch (Exception e){
            raLocaleBean.addMessageError("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage());
            log.info("Keystore could not be generated for user " + endEntityInformation.getUsername());
        }
    }

    public boolean isRenderGenerateCertificate(){
        if (isUserGeneratedToken()) {
            // If CSR is already uploaded, load its key algorithm and display it to end user
            if (isCsrPreSet() && !isCsrChanged) {
                selectKeyAlgorithmFromCsr();
            }
            return true;
        }
        return false;
    }

    /**
     * @return true if token is generated by user
     */
    public boolean isUserGeneratedToken(){
        return endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN;
    }

    public boolean isRenderGenerateKeyStoreJks(){
        if (endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN) {
            return false;
        }
        final KeyToValueHolder<EndEntityProfile> holder = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId());
        if (holder == null) {
            return false;
        }
        final EndEntityProfile endEntityProfile = holder.getValue();
        if (endEntityProfile == null) {
            return false;
        }
        final String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return availableKeyStores != null && availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_JKS));
    }

    public boolean isRenderGenerateKeyStorePkcs12(){
        if (endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN){
            return false;
        }
        KeyToValueHolder<EndEntityProfile> holder = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId());
        if (holder == null) {
            return false;
        }
        EndEntityProfile endEntityProfile = holder.getValue();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return availableKeyStores != null && availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_P12));
    }

    public boolean isRenderGenerateKeyStoreBcfks() {
        if (endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN) {
            return false;
        }
        KeyToValueHolder<EndEntityProfile> holder = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId());
        if (holder == null) {
            return false;
        }
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId()).getValue();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return availableKeyStores != null && availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_BCFKS));
    }

    public boolean isRenderGenerateKeyStorePem(){
        if(endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN){
            return false;
        }
        KeyToValueHolder<EndEntityProfile> holder = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId());
        if (holder == null) {
            return false;
        }
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId()).getValue();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return availableKeyStores != null && availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_PEM));
    }

    /**
     * Checks if key algorithm is already set in an earlier stage or by a CSR.
     * @return true if key algorithm is set in EEI or to be uploaded by CSR
     */
    public boolean isKeyAlgorithmPreSet() {
        return  (endEntityInformation.getExtendedInformation() != null && endEntityInformation.getExtendedInformation().getKeyStoreAlgorithmType() != null) ||
                endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN ||
                endEntityInformation.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY;
    }

    /**
     * Checks if a non-modifiable text displaying the previously set key algorithm should be shown.
     */
    public boolean isPreSetKeyAlgorithmRendered() {
        return endEntityInformation.getExtendedInformation() != null &&
               endEntityInformation.getExtendedInformation().getKeyStoreAlgorithmType() != null &&
               endEntityInformation.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY;
    }

    /**
     * Checks if a CSR has been uploaded in an earlier stage (before the finalize enrollment stage)
     * @return true if a CSR is set in EEI
     */
    public boolean isCsrPreSet() {
        return endEntityInformation.getExtendedInformation() != null && endEntityInformation.getExtendedInformation().getCertificateRequest() != null;
    }

    protected final void downloadToken(byte[] token, String responseContentType, String fileExtension) {
        if (token == null) {
            return;
        }
        // Download the token
        String fileName = CertTools.getPartFromDN(endEntityInformation.getDN(), "CN");
        if(fileName == null){
            fileName = "certificatetoken";
        }
        try {
            DownloadHelper.sendFile(token, responseContentType, fileName + fileExtension);
        } catch (IOException e) {
            log.info("Token " + fileName + " could not be downloaded", e);
            raLocaleBean.addMessageError("enroll_token_could_not_be_downloaded", fileName);
        }
    }

    /** @return true if the the CSR has been uploaded */
    public boolean isUploadCsrDoneRendered() {
        return selectedAlgorithm != null;
    }

    /** @return the current certificateRequest if available */
    public String getCertificateRequest() {
        if (StringUtils.isEmpty(certificateRequest)) {
            // Multi-line place holders are not allowed according to https://www.w3.org/TR/html5/forms.html#the-placeholder-attribute
            certificateRequest = raLocaleBean.getMessage("enroll_upload_csr_placeholder");
        }
        return certificateRequest;
    }

    /** @param certificateRequest the certificateRequest to set */
    public void setCertificateRequest(final String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }

    /** Backing method for upload CSR button (used for uploading pasted CSR) populating fields is handled by AJAX */
    public void uploadCsr() {
    }

    /** Resets selected key algorithm and flags CSR as changed */
    public void uploadCsrChange() {
        selectedAlgorithm = null;
        isCsrChanged = true;
    }

    /** Updates selected algorithm with key algorithm and key size from the CSR preset in EEI. */
    protected void selectKeyAlgorithmFromCsr() {
        if (endEntityInformation.getExtendedInformation() != null) {
            try {
                final RequestMessage certRequest = RequestMessageUtils.parseRequestMessage(endEntityInformation.getExtendedInformation().getCertificateRequest());
                if (certRequest == null) {
                    throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));
                }
                final String keySpecification = AlgorithmTools.getKeySpecification(certRequest.getRequestPublicKey());
                final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(certRequest.getRequestPublicKey());
                selectedAlgorithm = keyAlgorithm + " " + keySpecification; // Save for later use
            } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_unknown_key_algorithm")));
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** Validate an uploaded CSR and store the extracted key algorithm and CSR for later use. */
    public void validateCsr(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        RaCsrTools.validateCsr(value, this, raLocaleBean, getCertificateProfile(), requestId, false);
        try {
            RaCsrTools.validetaNumberOfFieldsInSubjectDn(authorizedEndEntityProfiles.get(getEndEntityInformation().getEndEntityProfileId()),
                    getCertificateRequest(), raLocaleBean, requestId, false);
        } catch (ValidatorException e) {
            setSelectedAlgorithm(null);
            certificateRequest = null;
            throw e;
        }
    }

    public boolean isRenderPassword() {
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId()).getValue();
        return !endEntityProfile.useAutoGeneratedPasswd();
    }

    private CertificateProfile getCertificateProfile() {
        if (this.certificateProfile == null) {
            EndEntityInformation ei = getEndEntityInformation();
            if (ei != null) {
                this.certificateProfile = raMasterApiProxyBean.getCertificateProfile(ei.getCertificateProfileId());
            }
        }
        return this.certificateProfile;
    }

    /** @return the current availableAlgorithms as determined by state of dependencies */
    public List<SelectItem> getAvailableAlgorithmSelectItems() {
        final List<SelectItem> availableAlgorithmSelectItems = new ArrayList<>();
        final CertificateProfile certificateProfile = getCertificateProfile();
        if (certificateProfile!=null) {
            final List<String> availableKeyAlgorithms = certificateProfile.getAvailableKeyAlgorithmsAsList();
            final List<Integer> availableBitLengths = certificateProfile.getAvailableBitLengthsAsList();
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
                for (final int availableBitLength : availableBitLengths) {
                    if (availableBitLength == 1024) {
                        availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_DSA + "_" + availableBitLength,
                                AlgorithmConstants.KEYALGORITHM_DSA + " " + availableBitLength + " bits"));
                    }
                }
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
                for (final int availableBitLength : availableBitLengths) {
                    if (availableBitLength >= 1024) {
                        availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_RSA + "_" + availableBitLength,
                                AlgorithmConstants.KEYALGORITHM_RSA + " " + availableBitLength + " bits"));
                    }
                }
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ED25519)) {
                availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED25519,
                        AlgorithmConstants.KEYALGORITHM_ED25519));
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ED448)) {
                availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED448,
                        AlgorithmConstants.KEYALGORITHM_ED448));
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                final Set<String> ecChoices = new HashSet<>();
                if (certificateProfile.getAvailableEcCurvesAsList().contains(CertificateProfile.ANY_EC_CURVE)) {
                    for (final String ecNamedCurve : AlgorithmTools.getNamedEcCurvesMap(false).keySet()) {
                        if (CertificateProfile.ANY_EC_CURVE.equals(ecNamedCurve)) {
                            continue;
                        }
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve);
                        if (availableBitLengths.contains(bitLength)) {
                            ecChoices.add(ecNamedCurve);
                        }
                    }
                }
                ecChoices.addAll(certificateProfile.getAvailableEcCurvesAsList());
                ecChoices.remove(CertificateProfile.ANY_EC_CURVE);
                final List<String> ecChoicesList = new ArrayList<>(ecChoices);
                Collections.sort(ecChoicesList);
                for (final String ecNamedCurve : ecChoicesList) {
                    if (!AlgorithmTools.isKnownAlias(ecNamedCurve)) {
                        log.warn("Ignoring unknown curve " + ecNamedCurve + " from being displayed in the RA web.");
                        continue;
                    }
                    availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ECDSA + "_" + ecNamedCurve, AlgorithmConstants.KEYALGORITHM_ECDSA + " "
                                    + StringTools.getAsStringWithSeparator(" / ", AlgorithmTools.getAllCurveAliasesFromAlias(ecNamedCurve))));
                }
            }
            if (WebConfiguration.isPQCEnabled()) {
                for (String algorithm : availableKeyAlgorithms) {
                    if (AlgorithmTools.isPQC(algorithm)) {
                        availableAlgorithmSelectItems.add(new SelectItem(algorithm));
                    }
                }
            }
            for (final String algName : AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithms()) {
                if (availableKeyAlgorithms.contains(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName))) {
                    for (final String subAlg : CesecoreConfiguration.getExtraAlgSubAlgs(algName)) {
                        final String name = CesecoreConfiguration.getExtraAlgSubAlgName(algName, subAlg);
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(name);
                        if (availableBitLengths.contains(bitLength)) {
                            availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName) + "_" + name,
                                    CesecoreConfiguration.getExtraAlgSubAlgTitle(algName, subAlg)));
                        } else {
                            if (log.isTraceEnabled()) {
                                log.trace("Excluding " + name + " from enrollment options since bit length " + bitLength + " is not available.");
                            }
                        }
                    }
                }
            }
            if (availableAlgorithmSelectItems.size() < 1) {
                availableAlgorithmSelectItems.add(new SelectItem(null, raLocaleBean.getMessage("enroll_select_ka_nochoice"), raLocaleBean.getMessage("enroll_select_ka_nochoice"), true));
            }
        }
        EnrollMakeNewRequestBean.sortSelectItemsByLabel(availableAlgorithmSelectItems);
        return availableAlgorithmSelectItems;
    }

    public boolean canEndEntityEnroll(final EndEntityInformation endEntity) {
        // raMasterApiProxyBean.isAllowedToEnrollByStatus is not available if the CA runs an
        // older version than 7.10.0, so only call it if needed.
        if (endEntity == null) {
            return false;
        }
        int status = endEntity.getStatus();
        if (status == EndEntityConstants.STATUS_NEW || status == EndEntityConstants.STATUS_FAILED ||
            status == EndEntityConstants.STATUS_INPROCESS || status == EndEntityConstants.STATUS_KEYRECOVERY) {
            return true;
        } else {
            if (raMasterApiProxyBean.canEndEntityEnroll(raAuthenticationBean.getAuthenticationToken(), endEntity.getUsername())) {
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Wrong End Entity status for the username='" + endEntity.getUsername() + "', "+endEntity.getStatus());
                }
                return false;
            }
        }
    }
    
    public boolean isKeyRecoverable() {
        return getEndEntityInformation().getKeyRecoverable();
    }

    //-----------------------------------------------------------------
    //Getters/setters

    /** @return EEI of current end entity*/
    public EndEntityInformation getEndEntityInformation() {
        return endEntityInformation;
    }

    /** @param endEntityInformation EEI to be set*/
    public void setEndEntityInformation(EndEntityInformation endEntityInformation) {
        this.endEntityInformation = endEntityInformation;
        statusAllowsEnrollment = canEndEntityEnroll(endEntityInformation);
    }

    public boolean isStatusAllowsEnrollment() {
        return statusAllowsEnrollment;
    }

     /** @return the requestId */
    public String getRequestId() {
        return requestId;
    }

    /** @param requestId the requestId to set */
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    /** @return the request status*/
    public int getRequestStatus() {
        return requestStatus;
    }

    /** @param requestStatus the request status to be set*/
    public void setRequestStatus(int requestStatus) {
        this.requestStatus = requestStatus;
    }

    /** @return key algorithm and size to be used for keystore / certificate enrollment. Format: 'algorithm keysize' */
    public String getSelectedAlgorithm() {
        return selectedAlgorithm;
    }

    /** @param selectedAlgorithm sets the algorithm and key size to be used for keystore / certificate enrollment. Format: 'algorithm keysize'*/
    public void setSelectedAlgorithm(String selectedAlgorithm) {
        this.selectedAlgorithm = selectedAlgorithm;
    }

    /**
     * @return the generatedToken (.p12, .jks or .pem without full chain)
     */
    public byte[] getGeneratedToken() {
        return generatedToken;
    }

    /** @param generatedToken byte array of generated token*/
    public void setGeneratedToken(byte[] generatedToken) {
        this.generatedToken = generatedToken;
    }

    public String getPreSetKeyAlgorithm() {
        if (endEntityInformation.getExtendedInformation() == null) {
            return null;
        }
        final String subType = endEntityInformation.getExtendedInformation().getKeyStoreAlgorithmSubType(); // can be null, but that's ok
        return endEntityInformation.getExtendedInformation().getKeyStoreAlgorithmType() + (subType != null ? (" " + subType) : "");
    }
    
    /**
     * Populates the end entities ExtendedInformation fields for the key specification 
     * (keyStoreAlgorithmType and keyStoreAlgorithmSubType).
     * 
     * @param endEntity the end entity.
     * @param keySpec the key specification.
     * 
     * @return true, if the end entities ExtendedInformation fields for the key specification have been changed.  
     */
    private boolean setPreSetKeyAlgorithm(final EndEntityInformation endEntity, final String keySpec) {
        boolean result = false;
        if (keySpec != null) {
            final int index = keySpec.indexOf('_');
            final int length = keySpec.length();
            ExtendedInformation eeInfo = endEntity.getExtendedInformation();
            if (eeInfo == null) {
                eeInfo = new ExtendedInformation();
                endEntityInformation.setExtendedInformation(eeInfo);
            }
            if (index > -1 && index != length) {
                final String alg = keySpec.substring(0, index); // i.e. RSA.
                final String spec = keySpec.substring(index + 1, keySpec.length()); // i.e. 2048 or null.
                result = !alg.equals(eeInfo.getKeyStoreAlgorithmType()) || !spec.equals(eeInfo.getKeyStoreAlgorithmSubType());
                eeInfo.setKeyStoreAlgorithmType(alg);
                eeInfo.setKeyStoreAlgorithmSubType(spec);
            } else {
                result = !keySpec.equals(eeInfo.getKeyStoreAlgorithmType());
                eeInfo.setKeyStoreAlgorithmType(keySpec);
            }
            if (result) {
                log.info("Change end entity key specification to '" + keySpec + "'");
            }
        }
        return result;
    }

    public boolean isDeletePublicAccessRole() {
        return deletePublicAccessRole;
    }

    public void setDeletePublicAccessRole(boolean deletePublicAccessRole) {
        this.deletePublicAccessRole = deletePublicAccessRole;
    }

    public boolean isDeletePublicAccessRoleRendered(){
        return deletePublicAccessRoleRendered;
    }

    public void setDeletePublicAccessRoleRendered(boolean deletePublicAccessRoleRendered) {
        this.deletePublicAccessRoleRendered = deletePublicAccessRoleRendered;
    }
}
