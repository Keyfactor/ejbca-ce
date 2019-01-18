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

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.ValidatorException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Managed bean that backs up the enrollwithusername.xhtml page. Extends EnrollWithRequestIdBean to make use of common code
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EnrollWithUsernameBean extends EnrollWithRequestIdBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollWithUsernameBean.class);

    public static String PARAM_USERNAME = "username";
    public static String PARAM_ENROLLMENT_CODE = "enrollmentcode";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value = "#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;

    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    private String username;
    private String enrollmentCode;
    // Since enrollmentCode of the EnrollWithRequestIdBean is managed through JSF, and it won't let me set a password field
    // through GET param, we need this temporary var in order to be able to pass enrollment code in the URL
    private String paramEnrollmentCode;
    // Cache for certificate profile
    private CertificateProfile certificateProfile;

    @PostConstruct
    protected void postConstruct() {
        final HttpServletRequest httpServletRequest = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        username = httpServletRequest.getParameter(EnrollWithUsernameBean.PARAM_USERNAME);
        paramEnrollmentCode = httpServletRequest.getParameter(EnrollWithUsernameBean.PARAM_ENROLLMENT_CODE);
        super.setRaAuthenticationBean(raAuthenticationBean);
        super.postConstruct();
    }

    /** Disable the username field if we have passwed username as a parameter in the URL (i.e. &username=tomas).
     * User friendly as the user can not accidentally change the pre defined username */
    public boolean isUsernameDisabled() {
        final HttpServletRequest httpServletRequest = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
        return httpServletRequest.getParameter(EnrollWithUsernameBean.PARAM_USERNAME) != null;
    }
    
    @Override
    public void reset() {
        this.certificateProfile = null;
        enrollmentCode = null;        
        super.reset();
    }
    
    /**
     * Check the status end entity and the enrollment code validity
     */
    public void checkUsernameEnrollmentCode() {
        if (StringUtils.isNotEmpty(username)) {
            final EndEntityInformation endEntityInformation = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), username);
            if (endEntityInformation == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not find  End Entity for the username='" + username + "'");
                }
                raLocaleBean.addMessageError("enrollwithusername_user_not_found_or_wrongstatus_or_invalid_enrollmentcode", username);
                return;
            } else if(endEntityInformation.getStatus() == EndEntityConstants.STATUS_GENERATED){
                if (log.isDebugEnabled()) {
                    log.debug("End Entity status not NEW for the username='" + username + "', "+endEntityInformation.getStatus());
                }
                raLocaleBean.addMessageError("enrollwithusername_user_not_found_or_wrongstatus_or_invalid_enrollmentcode", username);
                return;
            }
            final String password;
            // Code for handling the case where we put enrollment code as a URL GET parameter, as well as when we enter it manually in the form
            if (StringUtils.isEmpty(getEnrollmentCode()) && StringUtils.isNotEmpty(paramEnrollmentCode)) {
                if (log.isDebugEnabled()) {
                    log.debug("Password for user '"+username+"' was provided as parameter, using this.");
                }
                password = paramEnrollmentCode;
            } else {
                password = getEnrollmentCode();
            }
            try {
                raMasterApiProxyBean.checkUserStatus(raAuthenticationBean.getAuthenticationToken(), username, password);
            } catch (NoSuchEndEntityException | AuthStatusException | AuthLoginException e) {
                if (log.isDebugEnabled()) {
                    log.debug("End Entity status failed status check for username='" + username + "', "+e.getMessage());
                }
                raLocaleBean.addMessageError("enrollwithusername_user_not_found_or_wrongstatus_or_invalid_enrollmentcode", username);
                return;
            }
            if (StringUtils.isEmpty(getEnrollmentCode()) && StringUtils.isNotEmpty(paramEnrollmentCode)) {
                endEntityInformation.setPassword(paramEnrollmentCode);
            } else {
                endEntityInformation.setPassword(getEnrollmentCode());
            }
            setEndEntityInformation(endEntityInformation);
        }
    }

    @Override
    public boolean isFinalizeEnrollmentRendered() {
        final EndEntityInformation endEntityInformation = getEndEntityInformation();
        return (endEntityInformation != null && (endEntityInformation.getStatus() == EndEntityConstants.STATUS_NEW || endEntityInformation.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY));
    }

    public boolean isParamEnrollmentCodeEmpty() {
        return StringUtils.isEmpty(paramEnrollmentCode);
    }

    private String certificateRequest;
    
    /** @return true if the the CSR has been uploaded */
    public boolean isUploadCsrDoneRendered() {
        return getSelectedAlgorithm() != null;
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

    /** Validate an uploaded CSR and store the extracted key algorithm and CSR for later use. */
    @Override
    public final void validateCsr(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        setSelectedAlgorithm(null);
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
                if (!certificateProfile.isKeyTypeAllowed(keyAlgorithm, keySpecification)) {
                    throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_key_algorithm_is_not_available", keyAlgorithm + "_" + keySpecification)));
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Ignoring algorithm validation on CSR because we can not find a Certificate Profile for user: "+username);
                }
            }
            setSelectedAlgorithm(keyAlgorithm + " " + keySpecification);
            // For yet unknown reasons, the setter is never when invoked during AJAX request
            certificateRequest = value.toString();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_unknown_key_algorithm")));
        }
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

    //-----------------------------------------------------------------
    //Getters/setters
    
    /** @return the username */
    public String getUsername() {
        return username;
    }

    /** @param username the username to set */
    public void setUsername(String username) {
        this.username = username;
    }

    /** @return the enrollment code */
    public String getEnrollmentCode() {
        return enrollmentCode;
    }

    /** @param enrollmentCode the enrollment code to set */
    public void setEnrollmentCode(String enrollmentCode) {
        this.enrollmentCode = enrollmentCode;
    }
}
