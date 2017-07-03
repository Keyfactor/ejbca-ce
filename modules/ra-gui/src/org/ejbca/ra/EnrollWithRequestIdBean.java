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
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.faces.validator.ValidatorException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.ErrorCode;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Managed bean that backs up the enrollwithrequestid.xhtml page
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EnrollWithRequestIdBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollWithRequestIdBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value = "#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;

    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    @ManagedProperty(value = "#{raLocaleBean}")
    protected RaLocaleBean raLocaleBean;

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    private CertificateProfile certificateProfile;
    private String requestId;
    private String requestUsername;
    private String selectedAlgorithm; 
    private String certificateRequest;
    private int requestStatus;
    private EndEntityInformation endEntityInformation;
    private byte[] generatedToken;
    private IdNameHashMap<CAInfo> authorizedCAInfos;
    private IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
    private boolean isCsrChanged;

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
                } else {
                    requestUsername = raApprovalRequestInfo.getEditableData().getUsername();
                }
                endEntityInformation = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), requestUsername);
                if (endEntityInformation == null) {
                    log.error("Could not find endEntity for the username='" + requestUsername + "'");
                }else if(endEntityInformation.getStatus() == EndEntityConstants.STATUS_GENERATED){
                    raLocaleBean.addMessageInfo("enrollwithrequestid_enrollment_with_request_id_has_already_been_finalized", Integer.parseInt(requestId));
                }else{
                    raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_approved", Integer.parseInt(requestId));
                }
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
        return (requestStatus == ApprovalDataVO.STATUS_APPROVED || requestStatus == ApprovalDataVO.STATUS_EXECUTED) && endEntityInformation != null && 
                (endEntityInformation.getStatus() == EndEntityConstants.STATUS_NEW || endEntityInformation.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY);
    }

    public void generateCertificatePem() {
        generateCertificate();
        if (generatedToken != null) {
            try {
                X509Certificate certificate = CertTools.getCertfromByteArray(generatedToken, X509Certificate.class);        
                byte[] pemToDownload = CertTools.getPemFromCertificateChain(Arrays.asList((Certificate) certificate));
                downloadToken(pemToDownload, "application/octet-stream", ".pem");
            } catch (CertificateParsingException | CertificateEncodingException e) {
                log.info(e);
            }            
        } else {
            log.debug("No token was generated an error meesage should have been logged");
        }
        reset();
    }

    public void generateCertificatePemFullChain() {
        generateCertificate();
        if (generatedToken != null) {
            try {
                X509Certificate certificate = CertTools.getCertfromByteArray(generatedToken, X509Certificate.class);
                CAInfo caInfo = authorizedCAInfos.get(endEntityInformation.getCAId()).getValue();
                LinkedList<Certificate> chain = new LinkedList<>(caInfo.getCertificateChain());
                chain.addFirst(certificate);
                byte[] pemToDownload = CertTools.getPemFromCertificateChain(chain);
                downloadToken(pemToDownload, "application/octet-stream", ".pem");
            } catch (CertificateParsingException | CertificateEncodingException e) {
                log.info(e);
            }
        } else {
            log.debug("No token was generated an error meesage should have been logged");
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
            log.debug("No token was generated an error meesage should have been logged");
        }
        reset();
    }

    protected final void generateCertificateAfterCheck(){
        try {
            generatedToken = raMasterApiProxyBean.createCertificate(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
            log.info(endEntityInformation.getTokenType() + " token has been generated for the end entity with username " +
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
        if (getEndEntityInformation().getExtendedinformation() == null) {
            getEndEntityInformation().setExtendedinformation(new ExtendedInformation());
        }
        byte[] certificateRequest = getEndEntityInformation().getExtendedinformation().getCertificateRequest();
        if (certificateRequest == null || isCsrChanged) {
            if (getCertificateRequest() == null) {
                raLocaleBean.addMessageError("enrollwithrequestid_could_not_find_csr_inside_enrollment_request_with_request_id", requestId);
                log.info("Could not find CSR inside enrollment request with ID " + requestId);
                return;
            }
            try {
                getEndEntityInformation().getExtendedinformation().setCertificateRequest(CertTools.getCertificateRequestFromPem(getCertificateRequest()).getEncoded());
            } catch (IOException e) {
                raLocaleBean.addMessageError("enroll_invalid_certificate_request");
                return;
            }
        }
        generateCertificateAfterCheck();
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
        reset();
    }

    public void generateKeyStorePem() {
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_PEM);
        generateKeyStore();
        downloadToken(generatedToken, "application/octet-stream", ".pem");
        reset();
    }

    protected void generateKeyStore(){
        // If key algorithm is missing from EEI, we need to fetch it from CSR / select list first
        if (!isKeyAlgorithmPreSet()) {
            if (StringUtils.isEmpty(selectedAlgorithm)) {
                raLocaleBean.addMessageError("enroll_no_key_algorithm");
                log.info("No key algorithm was provided.");
                return;            
            }
            final String[] parts = StringUtils.split(selectedAlgorithm, '_');
            if (parts == null || parts.length < 2) {
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
            final String keySpec = parts[1];
            if (StringUtils.isEmpty(keySpec)) {
                raLocaleBean.addMessageError("enroll_no_key_specification");
                log.info("No key specification was provided: "+selectedAlgorithm);
                return;
            }
            if (getEndEntityInformation().getExtendedinformation() == null) {
                getEndEntityInformation().setExtendedinformation(new ExtendedInformation());
            }
            getEndEntityInformation().getExtendedinformation().setKeyStoreAlgorithmType(keyAlg);
            getEndEntityInformation().getExtendedinformation().setKeyStoreAlgorithmSubType(keySpec);
        }

        try {
            byte[] keystoreAsByteArray = raMasterApiProxyBean.generateKeyStore(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
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
        if (endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN) {
            // If CSR is already uploaded, load its key algorithm and display it to end user
            if (isCsrPreSet() && !isCsrChanged) {
                selectKeyAlgorithmFromCsr();
            }
            return true;
        }
        return false;
    }

    public boolean isRenderGenerateKeyStoreJks(){
        if(endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN){
            return false;
        }
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId()).getValue();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return availableKeyStores != null && availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_JKS));
    }

    public boolean isRenderGenerateKeyStorePkcs12(){
        if(endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN){
            return false;
        }
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId()).getValue();
        if (endEntityProfile == null) {
            return false;
        }
        String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
        return availableKeyStores != null && availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_P12));
    }

    public boolean isRenderGenerateKeyStorePem(){
        if(endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN){
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
        return endEntityInformation.getExtendedinformation().getKeyStoreAlgorithmType() != null || 
                endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN ||
                endEntityInformation.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY;
    }
    
    /**
     * Checks if a non-modifiable text displaying the previously set key algorithm should be shown.
     */
    public boolean isPreSetKeyAlgorithmRendered() {
        return endEntityInformation.getExtendedinformation().getKeyStoreAlgorithmType() != null &&
                endEntityInformation.getTokenType() != EndEntityConstants.TOKEN_USERGEN &&
                endEntityInformation.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY;
    }
    
    /**
     * Checks if a CSR has been uploaded in an earlier stage (before the finalize enrollment stage)
     * @return true if a CSR is set in EEI
     */
    public boolean isCsrPreSet() {
        return endEntityInformation.getExtendedinformation().getCertificateRequest() != null;
    }

    private final void downloadToken(byte[] token, String responseContentType, String fileExtension) {
        if (token == null) {
            return;
        }
        //Download the token
        FacesContext fc = FacesContext.getCurrentInstance();
        ExternalContext ec = fc.getExternalContext();
        ec.responseReset(); // Some JSF component library or some Filter might have set some headers in the buffer beforehand. We want to get rid of them, else it may collide.
        ec.setResponseContentType(responseContentType);
        ec.setResponseContentLength(token.length);
        String fileName = CertTools.getPartFromDN(endEntityInformation.getDN(), "CN");
        if(fileName == null){
            fileName = "certificatetoken"; 
        }

        final String filename = StringTools.stripFilename(fileName + fileExtension);
        ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + filename + "\""); // The Save As popup magic is done here. You can give it any file name you want, this only won't work in MSIE, it will use current request URL as file name instead.
        try (final OutputStream output = ec.getResponseOutputStream()) {
            output.write(token);
            output.flush();
            fc.responseComplete(); // Important! Otherwise JSF will attempt to render the response which obviously will fail since it's already written with a file and closed.
        } catch (IOException e) {
            log.info("Token " + filename + " could not be downloaded", e);
            raLocaleBean.addMessageError("enroll_token_could_not_be_downloaded", filename);
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
        try {
            PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(endEntityInformation.getExtendedinformation().getCertificateRequest());
            final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(pkcs10CertificationRequest);
            final String keySpecification = AlgorithmTools.getKeySpecification(jcaPKCS10CertificationRequest.getPublicKey());
            final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(jcaPKCS10CertificationRequest.getPublicKey());
            selectedAlgorithm = keyAlgorithm + " " + keySpecification; // Save for later use
        } catch (IOException e) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_unknown_key_algorithm")));
        }
    }
    
    /** Validate an uploaded CSR and store the extracted key algorithm and CSR for later use. */
    public void validateCsr(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        selectedAlgorithm = null;
        final String valueStr = value.toString();
        if (valueStr != null && valueStr.length() > EnrollMakeNewRequestBean.MAX_CSR_LENGTH) {
            log.info("CSR uploaded was too large: "+valueStr.length());
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));            
        }
        PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(valueStr);
        if (pkcs10CertificateRequest == null) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));
        }

        //Get public key algorithm from CSR and check if it's allowed in certificate profile
        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(pkcs10CertificateRequest);
        try {
            final String keySpecification = AlgorithmTools.getKeySpecification(jcaPKCS10CertificationRequest.getPublicKey());
            final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(jcaPKCS10CertificationRequest.getPublicKey());
            // If we have an End Entity, use this to verify that the algorithm and keyspec are allowed
            final CertificateProfile certificateProfile = getCertificateProfile();
            if (certificateProfile != null) {
                final List<String> availableKeyAlgorithms = certificateProfile.getAvailableKeyAlgorithmsAsList();
                final List<String> availableEcCurves = certificateProfile.getAvailableEcCurvesAsList(); 
                final List<Integer> availableBitLengths = certificateProfile.getAvailableBitLengthsAsList();
                try {
                    if ( !availableKeyAlgorithms.contains(keyAlgorithm) || 
                            (!availableEcCurves.contains(keySpecification) && !availableBitLengths.contains(Integer.parseInt(keySpecification))) ) {
                        throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_key_algorithm_is_not_available", keyAlgorithm + "_" + keySpecification)));
                    }
                } catch (NumberFormatException e) {
                    throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_key_algorithm_is_not_available", keyAlgorithm + "_" + keySpecification)));                    
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Ignoring algorithm validation on CSR because we can not find a Certificate Profile for request with ID: " + requestId);
                }
            }
            selectedAlgorithm = keyAlgorithm + " " + keySpecification; // Save for later use
            // For yet unknown reasons, the setter is never when invoked during AJAX request
            certificateRequest = value.toString();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_unknown_key_algorithm")));
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
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                final Set<String> ecChoices = new HashSet<>();
                final Map<String, List<String>> namedEcCurvesMap = AlgorithmTools.getNamedEcCurvesMap(false);
                if (certificateProfile.getAvailableEcCurvesAsList().contains(CertificateProfile.ANY_EC_CURVE)) {
                    final String[] keys = namedEcCurvesMap.keySet().toArray(new String[namedEcCurvesMap.size()]);
                    for (final String ecNamedCurve : keys) {
                        if (CertificateProfile.ANY_EC_CURVE.equals(ecNamedCurve)) {
                            continue;
                        }
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve);
                        if (availableBitLengths.contains(Integer.valueOf(bitLength))) {
                            ecChoices.add(ecNamedCurve);
                        }
                    }
                }
                ecChoices.addAll(certificateProfile.getAvailableEcCurvesAsList());
                ecChoices.remove(CertificateProfile.ANY_EC_CURVE);
                final List<String> ecChoicesList = new ArrayList<>(ecChoices);
                Collections.sort(ecChoicesList);
                for (final String ecNamedCurve : ecChoicesList) {
                    availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ECDSA + "_" + ecNamedCurve, AlgorithmConstants.KEYALGORITHM_ECDSA + " "
                            + StringTools.getAsStringWithSeparator(" / ", namedEcCurvesMap.get(ecNamedCurve))));
                }
            }
            for (final String algName : CesecoreConfiguration.getExtraAlgs()) {
                if (availableKeyAlgorithms.contains(CesecoreConfiguration.getExtraAlgTitle(algName))) {
                    for (final String subAlg : CesecoreConfiguration.getExtraAlgSubAlgs(algName)) {
                        final String name = CesecoreConfiguration.getExtraAlgSubAlgName(algName, subAlg);
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(name);
                        if (availableBitLengths.contains(Integer.valueOf(bitLength))) {
                            availableAlgorithmSelectItems.add(new SelectItem(CesecoreConfiguration.getExtraAlgTitle(algName) + "_" + name,
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

    //-----------------------------------------------------------------
    //Getters/setters
    
    /** @return EEI of current end entity*/
    public EndEntityInformation getEndEntityInformation() {
        return endEntityInformation;
    }

    /** @param endEntityInformation EEI to be set*/
    public void setEndEntityInformation(EndEntityInformation endEntityInformation) {
        this.endEntityInformation = endEntityInformation;
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
        return endEntityInformation.getExtendedinformation().getKeyStoreAlgorithmType() + " " + endEntityInformation.getExtendedinformation().getKeyStoreAlgorithmSubType();
    }
}
