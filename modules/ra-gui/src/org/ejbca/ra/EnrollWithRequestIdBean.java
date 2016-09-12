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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.cesecore.ErrorCode;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
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
    private RaLocaleBean raLocaleBean;

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    private String requestId;
    private int requestStatus;
    private EndEntityInformation endEntityInformation;
    private byte[] generatedToken;
    private String password;
    private IdNameHashMap<CAInfo> authorizedCAInfos;
    private IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<EndEntityProfile>();

    @PostConstruct
    private void postConstruct() {
        HttpServletRequest httpServletRequest = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        this.authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(raAuthenticationBean.getAuthenticationToken());
        requestId = httpServletRequest.getParameter(EnrollMakeNewRequestBean.PARAM_REQUESTID);
        this.authorizedCAInfos = raMasterApiProxyBean.getAuthorizedCAInfos(raAuthenticationBean.getAuthenticationToken());
        reset();
    }

    public void reset() {
        requestStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        endEntityInformation = null;
    }

    /**
     * Check the status of request ID
     */
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
                String username = raApprovalRequestInfo.getEditableData().getUsername();
                endEntityInformation = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), username);
                if (endEntityInformation == null) {
                    log.error("Could not find endEntity for the username='" + username + "'");
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
        return (requestStatus == ApprovalDataVO.STATUS_APPROVED || requestStatus == ApprovalDataVO.STATUS_EXECUTED) && endEntityInformation.getStatus() == EndEntityConstants.STATUS_NEW;
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
                LinkedList<Certificate> chain = new LinkedList<Certificate>(caInfo.getCertificateChain());
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
                LinkedList<Certificate> chain = new LinkedList<Certificate>(caInfo.getCertificateChain());
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
    
    private final void generateCertificate(){
        byte[] certificateRequest = endEntityInformation.getExtendedinformation().getCertificateRequest();
        if (certificateRequest == null) {
            raLocaleBean.addMessageError("enrollwithrequestid_could_not_find_csr_inside_enrollment_request_with_request_id", requestId);
            log.info("Could not find CSR inside enrollment request with ID " + requestId);
            return;
        }
        try {
            generatedToken = raMasterApiProxyBean.createCertificate(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
            log.info(endEntityInformation.getTokenType() + " token has been generated for the end entity with username " +
                    endEntityInformation.getUsername());
        } catch (AuthorizationDeniedException e){
            raLocaleBean.addMessageInfo("enroll_unauthorized_operation", e.getMessage());
            log.info("You are not authorized to execute this operation", e);
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
    
    private final void generateKeyStore(){
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
            log.info("You are not authorized to execute this operation", e);
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
        return endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN;
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
        OutputStream output = null;
        try {
            output = ec.getResponseOutputStream();
            output.write(token);
            output.flush();
            fc.responseComplete(); // Important! Otherwise JSF will attempt to render the response which obviously will fail since it's already written with a file and closed.
        } catch (IOException e) {
            log.info("Token " + filename + " could not be downloaded", e);
            raLocaleBean.addMessageError("enroll_token_could_not_be_downloaded", filename);
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                }
            }
        }
    }

    public boolean isRenderPassword() {
        EndEntityProfile endEntityProfile = authorizedEndEntityProfiles.get(endEntityInformation.getEndEntityProfileId()).getValue();
        return !endEntityProfile.useAutoGeneratedPasswd();
    }

    //-----------------------------------------------------------------
    //Getters/setters
    public EndEntityInformation getEndEntityInformation() {
        return endEntityInformation;
    }

    public void setEndEntityInformation(EndEntityInformation endEntityInformation) {
        this.endEntityInformation = endEntityInformation;
    }

    /**
     * @return the requestId
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public int getRequestStatus() {
        return requestStatus;
    }

    public void setRequestStatus(int requestStatus) {
        this.requestStatus = requestStatus;
    }

    /**
     * @return the generatedToken (.p12, .jks or .pem without full chain)
     */
    public byte[] getGeneratedToken() {
        return generatedToken;
    }

    public void setGeneratedToken(byte[] generatedToken) {
        this.generatedToken = generatedToken;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * @param password the password to set
     */
    public void setPassword(String password) {
        this.password = password;
    }
    
    
}
