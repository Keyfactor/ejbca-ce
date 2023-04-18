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
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
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
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ra.EnrollMakeNewRequestBean.KeyPairGeneration;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;

/**
 * Managed bean that backs up the enrollwithusername.xhtml page. Extends EnrollWithRequestIdBean to make use of common code
 */
@Named
@ViewScoped
public class EnrollWithUsernameBean extends EnrollWithRequestIdBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollWithUsernameBean.class);

    public static String PARAM_USERNAME = "username";
    public static String PARAM_ENROLLMENT_CODE = "enrollmentcode";
    public static String PARAM_REQUESTID = "requestId";

    private boolean renderNonModifiableTemplates = false;
    private String selectedEndEntityProfile;    
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;

    @Override
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
    
    //SSH enrollment
    private String sshPublicKey;
    private boolean sshEnrollmentMode;
    private boolean validSshPubKey;

    @PostConstruct
    @Override
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
     * Check the status of the end entity and the enrollment code validity
     */
    public void checkUsernameEnrollmentCode() {
        if (StringUtils.isNotEmpty(username)) {
            final EndEntityInformation endEntityInformation = raMasterApiProxyBean.searchUserWithoutViewEndEntityAccessRule(raAuthenticationBean.getAuthenticationToken(), username);
            if (!canEndEntityEnroll(endEntityInformation)) {
                if (log.isDebugEnabled() && endEntityInformation == null) {
                    log.debug("Could not find End Entity for the username='" + username + "'");
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
            
            sshEnrollmentMode = getCertificateProfile().getType() == CertificateConstants.CERTTYPE_SSH;
            if (username.equals("superadmin")) {
                RaCertificateSearchResponse raCertificateSearchResponse = raMasterApiProxyBean.searchForCertificatesByUsername(raAuthenticationBean.getAuthenticationToken(), username);
                if (raCertificateSearchResponse.getCdws().size() == 0) {
                    setDeletePublicAccessRoleRendered(true);
                }
            }
        }
    }

    @Override
    public boolean isFinalizeEnrollmentRendered() {
        return isStatusAllowsEnrollment() && getEndEntityInformation()!=null;
    }

    public boolean isParamEnrollmentCodeEmpty() {
        return StringUtils.isEmpty(paramEnrollmentCode);
    }

    private String certificateRequest;
    
    /** @return true if the the CSR has been uploaded */
    @Override
    public boolean isUploadCsrDoneRendered() {
        return getSelectedAlgorithm() != null;
    }
    
    /** @return the current certificateRequest if available */
    @Override
    public String getCertificateRequest() {
        if (StringUtils.isEmpty(certificateRequest)) {
            // Multi-line place holders are not allowed according to https://www.w3.org/TR/html5/forms.html#the-placeholder-attribute
            certificateRequest = raLocaleBean.getMessage("enroll_upload_csr_placeholder");
        }
        return certificateRequest;
    }

    /** @param certificateRequest the certificateRequest to set */
    @Override
    public void setCertificateRequest(final String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }
    
    /** Backing method for upload CSR button (used for uploading pasted CSR) populating fields is handled by AJAX */
    @Override
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
        RequestMessage certRequest = RequestMessageUtils.parseRequestMessage(valueStr.getBytes());
        if (certRequest == null) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));
        }
        //Get public key algorithm from CSR and check if it's allowed in certificate profile or by PQC configuration
        try {
            final String keySpecification = AlgorithmTools.getKeySpecification(certRequest.getRequestPublicKey());
            final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(certRequest.getRequestPublicKey());
            if (AlgorithmTools.isPQC(keyAlgorithm) && !WebConfiguration.isPQCEnabled()) {
                throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_key_algorithm_is_not_available", keyAlgorithm + "_" + keySpecification)));
            }
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
            certificateRequest = valueStr;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            final String msg = raLocaleBean.getMessage("enroll_unknown_key_algorithm");
            if (log.isDebugEnabled()) {
                log.debug(msg + ": " + e.getMessage());
            }
            throw new ValidatorException(new FacesMessage(msg));
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e.getMessage());
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

    /**
     * The selection for the key specification is rendered if key algorithm is not taken from uploaded CSR.
     * 
     * @return true if the selectKeyAlgorithm should be rendered.
     */
    public boolean isSelectKeyAlgorithmRendered() {
        return !isUserGeneratedToken();
    }
    
    /**
     * @return true if fields that the client can't modify should still be rendered
     */
    public boolean isRenderNonModifiableTemplates() {
        return renderNonModifiableTemplates;
    }    
    
    /**
     * @return the current available key generation types as determined by state of dependencies for UI rendering
     */
    public List<SelectItem> getAvailableKeyPairGenerationSelectItems() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final KeyPairGeneration keyPairGeneration : getAvailableKeyPairGenerations()) {
            final String label = raLocaleBean.getMessage("enroll_key_pair_generation_" + keyPairGeneration.name().toLowerCase());
            ret.add(new SelectItem(keyPairGeneration.name(), label));
        }
        return ret;
    }
    
    /**
     * @return the current EndEntityProfile as determined by state of dependencies
     */
    public EndEntityProfile getEndEntityProfile() {
        if (getSelectedEndEntityProfile() != null) {
            final KeyToValueHolder<EndEntityProfile> temp = authorizedEndEntityProfiles.get(Integer.parseInt(getSelectedEndEntityProfile()));
            if (temp != null) {
                return temp.getValue();
            }
        }
        return null;
    }
    
    /**
     * @return the current lazy initialized selectedEndEntityProfile
     */
    public String getSelectedEndEntityProfile() {
        final List<Integer> availableEndEntityProfiles = getAvailableEndEntityProfiles();
        if (availableEndEntityProfiles.size() == 1) {
            setSelectedEndEntityProfile(String.valueOf(availableEndEntityProfiles.get(0)));
        }
        if (StringUtils.isNotEmpty(selectedEndEntityProfile) && !availableEndEntityProfiles.contains(Integer.parseInt(selectedEndEntityProfile))) {
            setSelectedEndEntityProfile(null);
        }
        return selectedEndEntityProfile;
    }
    
    /**
     * @param selectedEndEntityProfile the selectedEndEntityProfile to set
     */
    public void setSelectedEndEntityProfile(final String selectedEndEntityProfile) {
        if (!StringUtils.equals(selectedEndEntityProfile, this.selectedEndEntityProfile)) {
            this.selectedEndEntityProfile = selectedEndEntityProfile;
        }
    }
    
    /**
     * @return a List of available end entity profile identifiers
     */
    private List<Integer> getAvailableEndEntityProfiles() {
        return new ArrayList<>(authorizedEndEntityProfiles.idKeySet());
    }
    
    /**
     * @return the current available key generation types as determined by state of dependencies
     */
    private List<KeyPairGeneration> getAvailableKeyPairGenerations() {
        final List<KeyPairGeneration> ret = new ArrayList<>();
        final EndEntityProfile endEntityProfile = getEndEntityProfile();
        if (endEntityProfile != null) {
            final String availableKeyStores = endEntityProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0);
            if (availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_P12))
                    || availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_JKS))
                    || availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_PEM))) {
                ret.add(KeyPairGeneration.ON_SERVER);
            }
            if (availableKeyStores.contains(String.valueOf(SecConst.TOKEN_SOFT_BROWSERGEN))) {
                ret.add(KeyPairGeneration.PROVIDED_BY_USER);
            }
            ret.add(KeyPairGeneration.POSTPONE);
        }
        return ret;
    }
    
    public boolean isKeyRecoverable() {
        return getEndEntityInformation().getKeyRecoverable();
    }
    
    public boolean isRequestIdInfoRendered() {
        return requestId != null;
    }
    
    public final String getParamRequestId() {
        return PARAM_REQUESTID;
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
    
    //SSH certificate enrollment
    public String validateSshPublicKey(String publicKey) {
        validSshPubKey = false;
        if(StringUtils.isBlank(publicKey)) {
            return raLocaleBean.getMessage("enroll_ssh_pubkey_required");
        }
        try {
            SshKeyFactory.INSTANCE.extractSshPublicKeyFromFile(publicKey.getBytes());
            validSshPubKey = true;
        } catch (Exception e) {
            log.error("error: ", e);
            return raLocaleBean.getMessage("enroll_invalid_ssh_pub_key");
        }
        return null;
    }
    
    public String uploadSshPubKey() {
        return "";
    }
    
    public final void validateSshPublicKey(FacesContext context, UIComponent component, Object value) throws ValidatorException {
        String input = value.toString();
        String msg = validateSshPublicKey(input);
        if(msg!=null) {
            throw new ValidatorException(new FacesMessage(msg));
        }
    }
    
    public String getSshPublicKey() {
        return sshPublicKey;
    }

    public void setSshPublicKey(String sshPublicKey) {
        this.sshPublicKey = sshPublicKey;
    }
    
    public boolean getSshEnrollmentMode() {
        return sshEnrollmentMode;
    }
    
    public boolean isValidSshPubKey() {
        return validSshPubKey;
    }

    public void generateSshCertificate() {
        validateSshPublicKey(sshPublicKey);
        if(!validSshPubKey) {
            return;
        }
        // extendedInformation SHOULD always be set with sshCustomData.sshCertificateType during EE creation
        getEndEntityInformation().getExtendedInformation().setCertificateRequest(sshPublicKey.getBytes());
        generateCertificateAfterCheck();
        if (getGeneratedToken() != null) {
            downloadToken(getGeneratedToken(), "application/octet-stream", "-cert.pub");
        } else {
            log.debug("No token was generated an error message should have been logged");
        }
        reset();
    }

}
