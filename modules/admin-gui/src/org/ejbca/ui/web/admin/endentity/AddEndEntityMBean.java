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
package org.ejbca.ui.web.admin.endentity;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.ejb.EJBException;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.faces.event.AjaxBehaviorEvent;
import jakarta.faces.model.SelectItem;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.MutablePair;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.standard.CabForumOrganizationIdentifier;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.certextensions.standard.QcStatement;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.UserView;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ietf.ldap.LDAPDN;

import com.keyfactor.ErrorCode;
import com.keyfactor.util.certificate.DnComponents;

/**
*
* JSF MBean backing add end entity page.
*
*/
@Named
@ViewScoped
public class AddEndEntityMBean extends EndEntityBaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CertificateProfileSessionLocal certProfileSession;
    @EJB
    private CaSessionLocal caSession;
    
    private String selectedEeProfileName = "EMPTY";
    private int selectedEeProfileId = 0;
    private String userName;
    private String passwordFieldValue;
    private String confirmPasswordFieldValue;
    private EndEntityProfile selectedEeProfile = null;
    private String maxLoginAttempts;
    private String maxLoginAttemptsStatus;
    private boolean useClearTextPasswordStorage;
    private String[] emailDomains;
    private String emailDomain;
    private String emailUserName;
    private String profileEmail;
    private String selectedSubjectDn;
    private boolean useAltNameEmail;
    private String selectedSubjectAltNameMultipleOptionsNoRFC822;
    private String selectedSubjectDirNameMultipleOptions;
    private String selectedSubjectAltName;

    /* Main Certificate Data */
    private int selectedCertProfileId = -1;
    private int selectedTokenId = -1;
    private int selectedCaId = -1;
    
    private String validityStartTimeValue = StringUtils.EMPTY;
    private String validityEndTimeValue = StringUtils.EMPTY;
    private String cardNumber;
    private String nameConstraintsPermitted;
    private String nameConstraintsExcluded;
    
    private String extensionData;
    private String psd2NcaName;
    private String psd2NcaId;
    private List<String> psd2PspRoles;
    private String cabfOrganizationIdentifier;
    private int numberOfRequests = 1;
    private int revocationStatus = RevokedCertInfo.NOT_REVOKED;
    private boolean sendNotification;
    private boolean usePrinting;
    private boolean useKeyRecovery = false;
    private GlobalConfiguration globalConfiguration;
    private String customSerialNumber;
    private List<SubjectDnFieldData> subjectDnFieldDatas;
    private List<SubjectAltNameFieldData> subjectAltNameFieldDatas;
    private List<SubjectDirAttrFieldData> subjectDirAttrFieldDatas;
    private MutablePair<Boolean, Boolean> keyRecoveryCheckboxStatus = new MutablePair<>();

    private String[] profileNames = null; 
    
    private EjbcaWebBean ejbcaWebBean;
    private RAInterfaceBean raBean;
    
    // Authentication check and audit log page access request
    @PostConstruct
    public void initialize() throws EndEntityException {

        try {
            if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR)) {
                throw new AuthorizationDeniedException("You are not authorized to view this page.");
            }

            final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();

            ejbcaWebBean = getEjbcaWebBean();

            globalConfiguration = ejbcaWebBean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR,
                    AccessRulesConstants.REGULAR_CREATEENDENTITY);

            raBean = SessionBeans.getRaBean(request);
            raBean.initialize(ejbcaWebBean);

            RequestHelper.setDefaultCharacterEncoding(request);
            initUserData();
        } catch (Exception e) {
            throw new EndEntityException("Error while initializing the class " + this.getClass().getCanonicalName(), e);
        }
    }

    public String getSelectedSubjectAltName() {
        return selectedSubjectAltName;
    }

    public void setSelectedSubjectAltName(String selectedSubjectAltName) {
        this.selectedSubjectAltName = selectedSubjectAltName;
    }
    
    public String getUserName() {
        return this.userName;
    }
    
    public void setUserName(final String userName) {
        this.userName = userName;
    }
    
    public String[] getAvailableEmailDomains() {
        return emailDomains;
    }

    public String getMaxLoginAttempts() {
        return maxLoginAttempts;
    }

    public void setMaxLoginAttempts(String maxLoginAttempts) {
        this.maxLoginAttempts = maxLoginAttempts;
    }    
    
    public boolean isMaxLoginAttemptsDisabled() {
        return selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0).equals("-1"); 
    }

    public String getSelectedEeProfileName() {
        return selectedEeProfileName;
    }

    public void setSelectedEeProfileName(String selectedEeProfileName) {
        this.selectedEeProfileName = selectedEeProfileName;
    }

    public List<SelectItem> getAvailableEndEntityProfiles() throws EndEntityProfileNotFoundException {
        final List<SelectItem> ret = new ArrayList<>();
        for(int i = 0; i < profileNames.length; i++) {
            int pId = raBean.getEndEntityProfileId(profileNames[i]);
            ret.add(new SelectItem(pId, profileNames[i]));

        }
        return ret;
    }
    
    public boolean isAllowedToAddEndEntity() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_CREATEENDENTITY);
    }
    
    public boolean isUsernameAutoGenerated() {
        return selectedEeProfile.isAutoGeneratedUsername();
    }

    public String getDefaultUsername() {
        return selectedEeProfile.getUsernameDefault();
    }
    
    public String getUsernameTitle() {
        if (selectedEeProfile.isAutoGeneratedUsername()) {
            return getEjbcaWebBean().getText("USERNAMEWILLBEAUTOGENERATED");
        } else {
            if (selectedEeProfile.getUseValidationForUsername()) {
                return "Must match format specified in profile. / Technical detail - the regex is " + selectedEeProfile.getUsernameDefaultValidation();
            } else {
                return getEjbcaWebBean().getText("FORMAT_ID_STR");
            }
        }
    }  
    
    public boolean isUseAutoGeneratedPassword() {
        return selectedEeProfile.useAutoGeneratedPasswd();
    }
    
    public String getPasswordFieldValue() {
        return this.passwordFieldValue;
    }
    
    public void setPasswordFieldValue(final String passwordFieldValue) {
        this.passwordFieldValue = passwordFieldValue;
    }
    
    public boolean isUseMaxFailedLoginAttempts() {
        return selectedEeProfile.getUse(EndEntityProfile.MAXFAILEDLOGINS, 0);
    }
    
    public boolean isMaxFailedLoginAttemptsModifiable() {
       return selectedEeProfile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0);
    }
    
    public String actionChangeEndEntityProfile(AjaxBehaviorEvent event) {
        
        this.selectedEeProfile = raBean.getEndEntityProfile(selectedEeProfileId);
        
        this.maxLoginAttempts = selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0).equals("-1") ? StringUtils.EMPTY
                : selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0);
        this.maxLoginAttemptsStatus = selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0).equals("-1") ? "unlimited" : "specified";
        
        this.useClearTextPasswordStorage = selectedEeProfile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE);
        this.emailDomains = selectedEeProfile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
        this.profileEmail = selectedEeProfile.getValue(EndEntityProfile.EMAIL,0);
        this.emailDomain = setDefaultEmailDomainFromProfile();
        this.cabfOrganizationIdentifier = selectedEeProfile.getCabfOrganizationIdentifier();
        this.numberOfRequests = selectedEeProfile.getAllowedRequests();
        this.setSendNotification(selectedEeProfile.getValue(EndEntityProfile.SENDNOTIFICATION,0).equals(EndEntityProfile.TRUE));
        this.setUsePrinting(selectedEeProfile.getPrintingDefault());
        this.useKeyRecovery = globalConfiguration.getEnableKeyRecovery()
                && ejbcaWebBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_KEYRECOVERY)
                && selectedEeProfile.getUse(EndEntityProfile.KEYRECOVERABLE, 0);

        /* Main Certificate Data */
        this.selectedCertProfileId = selectedEeProfile.getDefaultCertificateProfile();
        this.selectedCaId = selectedEeProfile.getDefaultCA();
        this.selectedTokenId = Integer.parseInt(selectedEeProfile.getValue(EndEntityProfile.DEFKEYSTORE,0));
        
        this.keyRecoveryCheckboxStatus.setLeft(selectedTokenId != SecConst.TOKEN_SOFT_BROWSERGEN && selectedEeProfile.getUse(EndEntityProfile.KEYRECOVERABLE, 0));
        this.keyRecoveryCheckboxStatus.setRight(selectedEeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE,0));
        
        final String issuanceRevocationReason = selectedEeProfile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
        if ((issuanceRevocationReason != null) && ((issuanceRevocationReason).length() > 0)) {
            setRevocationStatus((Integer.parseInt(issuanceRevocationReason)));
        }
        composeSubjectDnFieldsAndData();
        composeSubjectAltNameFieldAndData();
        composeSubjectDirAttrFieldsAndData();
        
        return "addendentity";
    }

    public int getSelectedEeProfileId() {
        return selectedEeProfileId;
    }

    public void setSelectedEeProfileId(int selectedEeProfileId) {
        this.selectedEeProfileId = selectedEeProfileId;
    }


    public String getMaxLoginAttemptsStatus() {
        return maxLoginAttemptsStatus;
    }

    public void setMaxLoginAttemptsStatus(String maxLoginAttemptsStatus) {
        this.maxLoginAttemptsStatus = maxLoginAttemptsStatus;
    }
    
    public void setUseClearTextPasswordStorage(boolean useClearTextPasswordStorage) {
        this.useClearTextPasswordStorage = useClearTextPasswordStorage;
    }
    
    public boolean isUseClearTextPasswordStorage() {
        return useClearTextPasswordStorage;
    }
    
    public boolean isClearTextPasswordRequired() {
        return selectedEeProfile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD,0);
    }

    public boolean isUseBatchGenerationPassword() {
        return selectedEeProfile.getUse(EndEntityProfile.CLEARTEXTPASSWORD,0);
    }
    
    public boolean isUseEmail() {
        return selectedEeProfile.getUse(EndEntityProfile.EMAIL,0);
    }
    
    public boolean isEmailModifiable() {
        return selectedEeProfile.isModifyable(EndEntityProfile.EMAIL,0);
    }

    public String getEmailDomain() {
        return emailDomain;
    }

    public void setEmailDomain(String selectedEmailDomain) {
        this.emailDomain = selectedEmailDomain;
    }

    public String getProfileEmail() {
        return profileEmail;
    }

    public void setProfileEmail(String profileEmail) {
        this.profileEmail = profileEmail;
    }
    
    
    public List<SubjectDnFieldData> getSubjectDnFieldsAndDatas() {
        return this.subjectDnFieldDatas;
    }
    
    public List<SubjectAltNameFieldData> getSubjectAltNameFieldDatas() {
        return this.subjectAltNameFieldDatas;
    }
    
    public List<SubjectDirAttrFieldData> getSubjectDirAttrFieldDatas() {
        return this.subjectDirAttrFieldDatas;
    }
    
    public String getEmailUserName() {
        return emailUserName;
    }

    public void setEmailUserName(String emailUserName) {
        this.emailUserName = emailUserName;
    }

    public String getSelectedSubjectDn() {
        return selectedSubjectDn;
    }

    public void setSelectedSubjectDn(String selectedSubjectDn) {
        this.selectedSubjectDn = selectedSubjectDn;
    }
    
    public boolean isProfileHasSubjectAltNameFields() {
        return selectedEeProfile.getSubjectAltNameFieldOrderLength() > 0;
    }

    public boolean isProfileHasSubjectDirAttrFields() {
        return selectedEeProfile.getSubjectDirAttrFieldOrderLength() > 0;
    }

    public boolean isUseAltNameEmail() {
        return useAltNameEmail;
    }

    public void setUseAltNameEmail(boolean useAltNameEmail) {
        this.useAltNameEmail = useAltNameEmail;
    }

    public String getSelectedSubjectAltNameMultipleOptionsNoRFC822() {
        return selectedSubjectAltNameMultipleOptionsNoRFC822;
    }

    public void setSelectedSubjectAltNameMultipleOptionsNoRFC822(String selectedSubjectAltNameMultipleOptionsNoRFC822) {
        this.selectedSubjectAltNameMultipleOptionsNoRFC822 = selectedSubjectAltNameMultipleOptionsNoRFC822;
    }

    public String getSelectedSubjectDirNameMultipleOptions() {
        return selectedSubjectDirNameMultipleOptions;
    }

    public void setSelectedSubjectDirNameMultipleOptions(String selectedSubjectDirNameMultipleOptions) {
        this.selectedSubjectDirNameMultipleOptions = selectedSubjectDirNameMultipleOptions;
    }
    
    public List<SelectItem> getAvailableCertProfiles() {
        List<SelectItem> profiles = new ArrayList<>();
        String[] availableCertProfileIds = selectedEeProfile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
        
        for (String profileId : availableCertProfileIds) {
            profiles.add(new SelectItem(profileId, certProfileSession.getCertificateProfileName(Integer.parseInt(profileId))));
        }
        return profiles;
    }

    public int getSelectedCertProfileId() {
        return selectedCertProfileId;
    }

    public void setSelectedCertProfileId(int selectedCertProfileId) {
        this.selectedCertProfileId = selectedCertProfileId;
    }
    
    
    public List<SelectItem> getAvailableTokens() {

        List<SelectItem> listOfTokens = new ArrayList<>();

        final String[] tokenTexts = SecConst.TOKENTEXTS;
        final int[] tokenIds = SecConst.TOKENIDS;

        String[] availableTokens = selectedEeProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);

        if (availableTokens != null) {
            for (int i = 0; i < availableTokens.length; i++) {
                for (int j = 0; j < tokenTexts.length; j++) {
                    if (tokenIds[j] == Integer.parseInt(availableTokens[i])) {
                        if (tokenIds[j] > SecConst.TOKEN_SOFT) {
                            listOfTokens.add(new SelectItem(tokenIds[j], tokenTexts[j]));
                        } else {
                            listOfTokens.add(new SelectItem(tokenIds[j], getEjbcaWebBean().getText(tokenTexts[j])));
                        }
                    }
                }
            }
        }
        return listOfTokens;
    }

    public int getSelectedTokenId() {
        return selectedTokenId;
    }

    public void setSelectedTokenId(int selectedTokenId) {
        this.selectedTokenId = selectedTokenId;
    }
    
    public boolean isRenderOtherCertDataSection() {
        return (selectedEeProfile.isCustomSerialNumberUsed()
        || selectedEeProfile.isValidityStartTimeUsed()
        || selectedEeProfile.isValidityEndTimeUsed()
        || selectedEeProfile.isCardNumberUsed()
        || selectedEeProfile.isNameConstraintsPermittedUsed()
        || selectedEeProfile.isNameConstraintsExcludedUsed()
        || selectedEeProfile.isPsd2QcStatementUsed()
        || selectedEeProfile.isCabfOrganizationIdentifierUsed());
    }
    
    public boolean isCustomSerialNumberUsed()  {
        return selectedEeProfile.isCustomSerialNumberUsed();
    }
    
    public boolean isValidityStartTimeUsed() {
        return selectedEeProfile.isValidityStartTimeUsed();
    }
    
    public String getValidityTimeHelpText() {
        return getEjbcaWebBean().getText("DATE_HELP") + getEjbcaWebBean().getDateExample() + " " + getEjbcaWebBean().getText("OR").toLowerCase() + " "
                + getEjbcaWebBean().getText("DAYS").toLowerCase() + ":" + getEjbcaWebBean().getText("HOURS").toLowerCase() + ":"
                + getEjbcaWebBean().getText("MINUTES").toLowerCase();
    }
    
    public String getValidityTimeTitle() {
        return getEjbcaWebBean().getText("FORMAT_ISO8601") + " " + getEjbcaWebBean().getText("OR") + "("
                + getEjbcaWebBean().getText("DAYS").toLowerCase() + ":" + getEjbcaWebBean().getText("HOURS").toLowerCase() + ":"
                + getEjbcaWebBean().getText("MINUTES").toLowerCase();
    }
    
    public String getValidityStartTimeValue() {
        final String validityStartTime = selectedEeProfile.getValidityStartTime();
        String startTime = StringUtils.EMPTY;
        if (validityStartTime != null && validityStartTime.trim().length() > 0) {
            startTime = getEjbcaWebBean().getISO8601FromImpliedUTCOrRelative(validityStartTime);
        }
        return startTime;
    }    
    
    public void setValidityStartTimeValue(final String validityStartTimeValue) {
        this.validityStartTimeValue = validityStartTimeValue;
    }
    
    public boolean isValidityStartTimeReadOnly() {
        return !selectedEeProfile.isValidityStartTimeModifiable();
    }
    
    public boolean isValidityStartTimeRequired() {
        return selectedEeProfile.isRequired(EndEntityProfile.STARTTIME, 0);
    }

    public boolean isValidityEndTimeUsed() {
        return selectedEeProfile.isValidityEndTimeUsed();
    }

    public String getValidityEndTimeValue() {
        final String validityEndTime = selectedEeProfile.getValidityEndTime();
        String endTime = StringUtils.EMPTY;
        if (validityEndTime != null && validityEndTime.trim().length() > 0) {
            endTime = getEjbcaWebBean().getISO8601FromImpliedUTCOrRelative(validityEndTime);
        }
        return endTime;
    }    

    public void setValidityEndTimeValue(final String validityEndTimeValue) {
        this.validityEndTimeValue = validityEndTimeValue;
    }
    
    public boolean isValidityEndTimeReadOnly() {
        return !selectedEeProfile.isValidityEndTimeModifiable();
    }
    
    public boolean isValidityEndTimeRequired() {
        return selectedEeProfile.isRequired(EndEntityProfile.ENDTIME, 0);
    }

    public boolean isCardNumberUsed() {
        return selectedEeProfile.isCardNumberUsed();
    }

    public String getCardNumber() {
        return cardNumber;
    }

    public void setCardNumber(String cardNumber) {
        this.cardNumber = cardNumber;
    }
    
    public boolean isCardNumberRequired() {
        return selectedEeProfile.isCardNumberRequired();
    }
    
    public boolean isNameConstraintsPermittedUsed() {
        return selectedEeProfile.isNameConstraintsPermittedUsed();
    }
    
    public String getNameConstraintsPermittedHelpText() {
        return getEjbcaWebBean().getText("EXT_PKIX_NC_PERMITTED_HELP1") + 
               getEjbcaWebBean().getText("EXT_PKIX_NC_PERMITTED_HELP2") +
               getEjbcaWebBean().getText("EXT_PKIX_NC_PERMITTED_HELP3");
    }
    
    public boolean isNameConstraintsPermittedRequired() {
        return selectedEeProfile.isNameConstraintsPermittedRequired();
    }
    
    public boolean isNameConstraintsExcludedUsed() {
        return selectedEeProfile.isNameConstraintsPermittedUsed();
    }
    
    public String getNameConstraintsExcludedHelpText() {
        return getEjbcaWebBean().getText("EXT_PKIX_NC_EXCLUDED_HELP1") + getEjbcaWebBean().getText("EXT_PKIX_NC_EXCLUDED_HELP2");
    }
    
    public boolean isNameConstraintsExcludedRequired() {
        return selectedEeProfile.isNameConstraintsPermittedRequired();
    }

    public String getNameConstraintsPermitted() {
        return nameConstraintsPermitted;
    }

    public void setNameConstraintsPermitted(String nameConstraintsPermitted) {
        this.nameConstraintsPermitted = nameConstraintsPermitted;
    }

    public String getNameConstraintsExcluded() {
        return nameConstraintsExcluded;
    }

    public void setNameConstraintsExcluded(String nameConstraintsExcluded) {
        this.nameConstraintsExcluded = nameConstraintsExcluded;
    }
    
    public boolean isUseExtensionData() {
        return selectedEeProfile.getUseExtensiondata();
    }
    
    public String getExtensionData() {
        return this.extensionData;
    }
    
    public void setExtensionData(final String extData) {
        this.extensionData = extData;
    }
    
    public boolean isPsd2QcStatementUsed() {
        return selectedEeProfile.isPsd2QcStatementUsed();
    }

    public String getPsd2NcaName() {
        return psd2NcaName;
    }

    public void setPsd2NcaName(String psd2NcaName) {
        this.psd2NcaName = psd2NcaName;
    }

    public String getPsd2NcaId() {
        return psd2NcaId;
    }

    public void setPsd2NcaId(String psd2NcaId) {
        this.psd2NcaId = psd2NcaId;
    }

    public List<String> getPsd2PspRoles() {
        return psd2PspRoles;
    }

    public void setPsd2PspRoles(List<String> psd2PspRoles) {
        this.psd2PspRoles = psd2PspRoles;
    }
    
    public List<SelectItem> getAvailablePsd2PspRoles() {

        final List<SelectItem> availablePsdPspRoles = new ArrayList<>();

        availablePsdPspRoles.add(new SelectItem("PSP_AS", getEjbcaWebBean().getText("PSD2_PSP_AS")));
        availablePsdPspRoles.add(new SelectItem("PSP_PI", getEjbcaWebBean().getText("PSD2_PSP_PI")));
        availablePsdPspRoles.add(new SelectItem("PSP_AI", getEjbcaWebBean().getText("PSD2_PSP_AI")));
        availablePsdPspRoles.add(new SelectItem("PSP_IC", getEjbcaWebBean().getText("PSD2_PSP_IC")));

        return availablePsdPspRoles;
    }

    public boolean isCabfOrganizationIdentifierUsed() {
        return selectedEeProfile.isCabfOrganizationIdentifierUsed();
    }

    public String getCabfOrganizationIdentifier() {
        return cabfOrganizationIdentifier;
    }

    public void setCabfOrganizationIdentifier(String cabfOrganizationIdentifier) {
        this.cabfOrganizationIdentifier = cabfOrganizationIdentifier;
    }
    
    public boolean isCabfOrganizationIdentifierReadOnly() {
        return !selectedEeProfile.isCabfOrganizationIdentifierModifiable();
    }
    
    public boolean isCabfOrganizationIdentifierRequired() {
        return selectedEeProfile.isCabfOrganizationIdentifierRequired();
    }
    
    public boolean isRenderOtherDataSection() {
        return selectedEeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0) 
                || useKeyRecovery
                || selectedEeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)
                || selectedEeProfile.getUse(EndEntityProfile.SENDNOTIFICATION, 0) 
                || selectedEeProfile.getUsePrinting();
    }    
    
    
    public boolean isAllowedRequestsUsed() {
        return selectedEeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS,0);
    }
    
    public List<SelectItem> getAllowedRequests() {

        List<SelectItem> allowedRequestsList = new ArrayList<>();

        for (int j = 0; j < 6; j++) {
            allowedRequestsList.add(new SelectItem(String.valueOf(j), String.valueOf(j)));
        }

        return allowedRequestsList;
    }    
    
    public int getNumberOfRequests() {
        return this.numberOfRequests;
    }
    
    public void setNumberOfRequests(final int numberOfRequests) {
        this.numberOfRequests = numberOfRequests;
    }
    
    public boolean isUseKeyRecovery() {
        return useKeyRecovery;
    }
    
    public boolean isKeyRecoveryRequired() {
        return selectedEeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE,0);
    }
    
    public boolean isUseIssuanceRevocationReason() {
        return selectedEeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
    }
    
    public boolean isIssuanceRevocationReasonDisabled() {
        return !selectedEeProfile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
    }

    public int getRevocationStatus() {
        return revocationStatus;
    }

    public void setRevocationStatus(int revocationStatus) {
        this.revocationStatus = revocationStatus;
    }
    
    public List<SelectItem> getIssuanceRevocationReasons() {

        final List<SelectItem> issuanceRevocationReasons = new ArrayList<>();
        

        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.NOT_REVOKED, getEjbcaWebBean().getText("ACTIVE")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                getEjbcaWebBean().getText("SUSPENDED") + ": " + getEjbcaWebBean().getText("REV_CERTIFICATEHOLD")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_UNSPECIFIED")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_KEYCOMPROMISE")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_CACOMPROMISE")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_AFFILIATIONCHANGED")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_SUPERSEDED,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_SUPERSEDED")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_CESSATIONOFOPERATION")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_PRIVILEGEWITHDRAWN")));
        issuanceRevocationReasons.add(new SelectItem(RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE,
                getEjbcaWebBean().getText("REVOKED") + ": " + getEjbcaWebBean().getText("REV_AACOMPROMISE")));

        return issuanceRevocationReasons;

    }
    
    public boolean isUseSendNotification() {
        return selectedEeProfile.getUse(EndEntityProfile.SENDNOTIFICATION,0);
    }
    
    public boolean isSendNotificationRequired() {
        return selectedEeProfile.isRequired(EndEntityProfile.SENDNOTIFICATION,0);
    }

    public boolean isSendNotification() {
        return sendNotification;
    }

    public void setSendNotification(boolean sendNotification) {
        this.sendNotification = sendNotification;
    }

    public boolean isUsePrintingEnabled() {
        return selectedEeProfile.getUsePrinting();
    }
    
    public boolean isPrintingRequired() {
        return selectedEeProfile.getPrintingRequired();
    }

    public boolean isUsePrinting() {
        return usePrinting;
    }

    public void setUsePrinting(boolean usePrinting) {
        this.usePrinting = usePrinting;
    }
    
    /**
     * Adds endentity using the parameters set in the GUI and if all the checks pass.
     * 
     * @throws ParseException
     * @throws ParameterException
     * @throws EndEntityExistsException
     * @throws CADoesntExistsException
     * @throws CertificateSerialNumberException
     * @throws AuthorizationDeniedException
     * @throws EndEntityProfileValidationException
     * @throws IllegalNameException
     * @throws CertificateExtensionException 
     */
    public void addUser()
            throws ParseException, ParameterException, EndEntityExistsException, CADoesntExistsException, CertificateSerialNumberException,
            AuthorizationDeniedException, EndEntityProfileValidationException, IllegalNameException, CertificateExtensionException {
        
        if (!doesPasswordAndConfirmationMatch()) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("PASSWORDSDOESNTMATCH"));
            return;
        }
        
        // User view initialization
        UserView newUserView = new UserView();
        newUserView.setEndEntityProfileId(selectedEeProfileId);
        newUserView = checkAndSetExtendedInformation(newUserView);

        try { // Fields require validation, order is somehow important!
            newUserView = checkAndSetUserNameAndPassword(newUserView);
            newUserView = checkAndSetLoginAttempts(newUserView);
            if (checkAndSetUserEmail(newUserView).isPresent()) {
                newUserView = checkAndSetUserEmail(newUserView).get();
            } else {
                return;
            }
            newUserView = checkAndSetSubjectDN(newUserView);
            newUserView = checkAndSetSubjectAltName(newUserView);
            newUserView = checkAndSetSubjectDirName(newUserView);
            newUserView = checkAndSetMainCertificateData(newUserView);
            newUserView = checkAndSetCustomSerialNumber(newUserView);

        } catch (EndEntityException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            return;
        }
        
        newUserView = checkAndSetCardNumber(newUserView);
        newUserView = checkAndSetMaxNumberOfRequests(newUserView);
        newUserView.setKeyRecoverable(keyRecoveryCheckboxStatus.left);
        newUserView.setSendNotification(sendNotification);
        newUserView.setPrintUserData(usePrinting);
        newUserView = checkAndSetRevokationReason(newUserView);
        newUserView = checkAndSetValidityTimes(newUserView);
        newUserView = checkAndSetPsd2QcStatement(newUserView);
        newUserView = checkAndSetCabfOrgId(newUserView);
        newUserView = checkAndSetNameConstraints(newUserView);

        finallyCreateUser(newUserView);
    }
    
    public String getCustomSerialNumber() {
        return customSerialNumber;
    }

    public void setCustomSerialNumber(String customSerialNumber) {
        this.customSerialNumber = customSerialNumber;
    }
    
    public List<SelectItem> getAvailableCas() {
        
        Map<Integer, List<Integer>> currentAvailableCas = raBean.getCasAvailableToEndEntity(selectedEeProfileId);
        List<SelectItem> availableCasList = new ArrayList<>();
        List<Integer> availableCasToSelectedEeProfile = currentAvailableCas.get(selectedCertProfileId);
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();

        if (Objects.nonNull(availableCasToSelectedEeProfile)) {
            for (final int caId : availableCasToSelectedEeProfile) {
                availableCasList.add(new SelectItem(caId, caIdToNameMap.get(caId)));
            }
        }

        return availableCasList;
    }

    public int getSelectedCaId() {
        return selectedCaId;
    }

    public void setSelectedCaId(int selectedCaId) {
        this.selectedCaId = selectedCaId;
    }
    
    public void redirectToAdminweb() throws IOException {
        final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
        ec.redirect(ec.getRequestContextPath());
    }
    
    public String reloadAddEndEntityPage() {
        return StringUtils.EMPTY;
    }
    
    public ImmutablePair<List<UserView>, Boolean> getAddedUsers() {
        List<UserView> addedUsersList = new ArrayList<>();
        final int numberOfRows = getEjbcaWebBean().getEntriesPerPage();
        final UserView[] addedUsers = raBean.getAddedUsers(numberOfRows);

        for (int i = 0; i < addedUsers.length; i++) {
            if (addedUsers[i] != null) {
                addedUsersList.add(addedUsers[i]);
            }
        }
        return new ImmutablePair<>(addedUsersList, (addedUsers != null && addedUsers.length > 0));
    }
    
    public String encodeUserName(final String userName) throws UnsupportedEncodingException {
        return java.net.URLEncoder.encode(userName, StandardCharsets.UTF_8);
    }
    
    public String getAddedUserCN(final UserView addedUser) {
        return addedUser.getSubjectDNField(DNFieldExtractor.CN,0);
    }

    public String getAddedUserOU(final UserView addedUser) {
        return addedUser.getSubjectDNField(DNFieldExtractor.OU,0);
    }

    public String getAddedUserO(final UserView addedUser) {
        return addedUser.getSubjectDNField(DNFieldExtractor.O,0);
    }

    public String getViewEndEntityPopupLink(final String username) {
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "ra/viewendentity.xhtml?username=" + username;
    }

    public String getEditEndEntityPopupLink(final String username) {
        return getEjbcaWebBean().getBaseUrl() + globalConfiguration.getAdminWebPath() + "ra/editendentity.xhtml?username=" + username;
    }

    public void setConfirmPasswordFieldValue(String confirmPasswordFieldValue) {
        this.confirmPasswordFieldValue = confirmPasswordFieldValue;
    }
    
    public String getConfirmPasswordFieldValue() {
        return this.confirmPasswordFieldValue;
    }
    
    public boolean isRenderReloadButton() {
        return getAddedUsers().left.size() > 0;
    }
    
    public void keyRecoveryCheckboxStatusUpdate() {

        boolean keyRecoveryCheckBoxDisabled = false;
        boolean keyRecoveryCheckBoxChecked = false;

        if (getSelectedTokenId() == SecConst.TOKEN_SOFT_BROWSERGEN) {
            keyRecoveryCheckBoxChecked = false;
            keyRecoveryCheckBoxDisabled = true;
        } else {
            if (selectedEeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE, 0)) {
                keyRecoveryCheckBoxDisabled = true;
            } else {
                keyRecoveryCheckBoxDisabled = false;
            }

            if (selectedEeProfile.getValue(EndEntityProfile.KEYRECOVERABLE, 0).equals(EndEntityProfile.TRUE)
                    || selectedEeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE, 0)) {
                keyRecoveryCheckBoxChecked = true;

            } else {
                keyRecoveryCheckBoxChecked = false;
            }
        }
        
        this.keyRecoveryCheckboxStatus.setLeft(keyRecoveryCheckBoxChecked);
        this.keyRecoveryCheckboxStatus.setRight(keyRecoveryCheckBoxDisabled);

    }

    public MutablePair<Boolean, Boolean> getKeyRecoveryCheckboxStatus() {
        return keyRecoveryCheckboxStatus;
    }

    public void setKeyRecoveryCheckboxStatus(MutablePair<Boolean, Boolean> keyRecoveryCheckboxStatus) {
        this.keyRecoveryCheckboxStatus = keyRecoveryCheckboxStatus;
    }
    
    public boolean isProfileEmailRequired() {
        return selectedEeProfile.isEmailRequired();
    }

    public boolean isPasswordRequiredInProfile() {
        return selectedEeProfile.isPasswordRequired() && !selectedEeProfile.isPasswordPreDefined();
    }
    
    public boolean isPasswordPreDefined() {
        return selectedEeProfile.isPasswordPreDefined();
    }
    
    private void initUserData() throws EndEntityProfileNotFoundException, EndEntityException {

        profileNames = (String[]) ejbcaWebBean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.CREATE_END_ENTITY).keySet().toArray(new String[0]);
        
        if (profileNames == null || profileNames.length == 0) {
            throw new EndEntityException(getEjbcaWebBean().getText("NOTAUTHORIZEDTOCREATEENDENTITY"));
        } else {
            this.selectedEeProfileId = raBean.getEndEntityProfileId(profileNames[0]);
            this.selectedEeProfile = raBean.getEndEntityProfile(selectedEeProfileId);
        }
        
        this.useClearTextPasswordStorage = selectedEeProfile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE);
        this.maxLoginAttemptsStatus = selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0).equals("-1") ? "unlimited" : "specified";
        
        this.emailDomains = selectedEeProfile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
        
        this.emailDomain = setDefaultEmailDomainFromProfile();
        this.profileEmail = selectedEeProfile.getValue(EndEntityProfile.EMAIL,0);
        this.cabfOrganizationIdentifier = selectedEeProfile.getCabfOrganizationIdentifier();

        this.useKeyRecovery = globalConfiguration.getEnableKeyRecovery()
                && ejbcaWebBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_KEYRECOVERY)
                && selectedEeProfile.getUse(EndEntityProfile.KEYRECOVERABLE, 0);

        final String issuanceRevocationReason = selectedEeProfile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
        if ((issuanceRevocationReason != null) && ((issuanceRevocationReason).length() > 0)) {
            setRevocationStatus((Integer.parseInt(issuanceRevocationReason)));
        }

        /* Main Certificate Data */
        this.selectedCertProfileId = selectedEeProfile.getDefaultCertificateProfile();
        this.selectedCaId = selectedEeProfile.getDefaultCA();
        this.selectedTokenId = Integer.parseInt(selectedEeProfile.getValue(EndEntityProfile.DEFKEYSTORE,0));
        
        this.keyRecoveryCheckboxStatus.setLeft(selectedTokenId != SecConst.TOKEN_SOFT_BROWSERGEN && selectedEeProfile.getUse(EndEntityProfile.KEYRECOVERABLE, 0));
        this.keyRecoveryCheckboxStatus.setRight(selectedEeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE,0));
        
        this.setSendNotification(selectedEeProfile.getValue(EndEntityProfile.SENDNOTIFICATION,0).equals(EndEntityProfile.TRUE));
        this.setUsePrinting(selectedEeProfile.getPrintingDefault());

        composeSubjectDnFieldsAndData();
        composeSubjectAltNameFieldAndData();
        composeSubjectDirAttrFieldsAndData();
    }
    
    private String setDefaultEmailDomainFromProfile() {
        if(!selectedEeProfile.isEmailModifiable() && emailDomains.length == 1) {
            return emailDomains[0];
        } else if (selectedEeProfile.isEmailModifiable()) {
            return selectedEeProfile.getValue(EndEntityProfile.EMAIL,0);
        } else {
            return StringUtils.EMPTY;
        }
    }

    private void composeSubjectAltNameFieldAndData() {

        this.subjectAltNameFieldDatas = new ArrayList<>();

        final int numberOfSubjectAltNameFields = selectedEeProfile.getSubjectAltNameFieldOrderLength();

        for (int i = 0; i < numberOfSubjectAltNameFields; i++) {
            
            final int[] fieldData = selectedEeProfile.getSubjectAltNameFieldsInOrder(i);
            int fieldType = fieldData[EndEntityProfile.FIELDTYPE];

            final boolean modifiable = selectedEeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean required = selectedEeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean isRFC822Name = EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME);
            final boolean useDataFromEmailField = selectedEeProfile.getUse(fieldData[EndEntityProfile.FIELDTYPE],fieldData[EndEntityProfile.NUMBER]);
            final boolean copyDataFromCN = selectedEeProfile.getCopy(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean isDnsName = EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNSNAME);
            final boolean isUpn = EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.UPN);
            String[] options = null;
            String fieldValue = null;
            String regex = null;
            String rfcName = null;
            String rfcDomain = null;
            String rfc822NameString = null;
            String upnDomain = null;
            String upnName = null;

            // Handle RFC822NAME separately
            if (isRFC822Name) {

                rfc822NameString = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                String[] rfc822NameArray = new String[2];
                rfc822NameArray = extractRfc822NameArray(rfc822NameString, rfc822NameArray);

                if (modifiable) {
                    rfcName = rfc822NameArray[0].trim();
                    rfcDomain = rfc822NameArray[1].trim();
                } else {
                    options = rfc822NameString.split(EndEntityProfile.SPLITCHAR);
                }
            } else {
                
                options = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                        .split(EndEntityProfile.SPLITCHAR);
                
                if(isUpn && modifiable) {
                    upnDomain = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                } 
                
                if (isUpn && !modifiable && options.length == 1) {
                    upnDomain = options[0];
                }

                if (options.length == 0 && copyDataFromCN) {
                    fieldValue = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                } else {
                    fieldValue = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                    final Map<String, Serializable> validation = selectedEeProfile.getValidation(fieldData[EndEntityProfile.FIELDTYPE],
                            fieldData[EndEntityProfile.NUMBER]);
                    regex = (validation != null ? (String) validation.get(RegexFieldValidator.class.getName()) : null);
                }
            }

            if (EndEntityProfile.isFieldImplemented(fieldType)) {
                final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
                
                SubjectAltNameFieldData subjectAltNameFieldData = new SubjectAltNameFieldData.Builder(label, modifiable, required)
                        .withFieldValue(fieldValue)
                        .withRFC822Name(isRFC822Name)
                        .withUseDataFromRFC822NameField(useDataFromEmailField && required)
                        .withRenderDataFromRFC822CheckBox(useDataFromEmailField)
                        .withCopyDataFromCN(copyDataFromCN)
                        .withDNSName(isDnsName)
                        .withRfcName(rfcName)
                        .withRfcDomain(rfcDomain)
                        .withOptions(options)
                        .withRegex(regex)
                        .withRfc822NameString(rfc822NameString)
                        .withUpn(isUpn)                        
                        .withUpnName(upnName)
                        .withUpnDomain(upnDomain)
                        .build();
                subjectAltNameFieldDatas.add(subjectAltNameFieldData);
            }
        }
    }

    private String[] extractRfc822NameArray(String rfc822NameString, String[] rfc822NameArray) {
        if (rfc822NameString.indexOf("@") != -1) {
            rfc822NameArray = rfc822NameString.split("@");
        } else {
            rfc822NameArray[0] = StringUtils.EMPTY;
            rfc822NameArray[1] = rfc822NameString;
        }
        return rfc822NameArray;
    }

    private void composeSubjectDnFieldsAndData() {

        this.subjectDnFieldDatas = new ArrayList<>();

        int numberOfSubjectDnFields = selectedEeProfile.getSubjectDNFieldOrderLength();

        for (int i = 0; i < numberOfSubjectDnFields; i++) {

            int[] fieldData = selectedEeProfile.getSubjectDNFieldsInOrder(i);

            final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
            final boolean required = selectedEeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean modifiable = selectedEeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean isEmailAddress = EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS);

            String[] options = null;
            String regex = null;
            String fieldValue = null;

            options = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                    .split(EndEntityProfile.SPLITCHAR);
            final Map<String, Serializable> validation = selectedEeProfile.getValidation(fieldData[EndEntityProfile.FIELDTYPE],
                    fieldData[EndEntityProfile.NUMBER]);
            regex = (validation != null ? (String) validation.get(RegexFieldValidator.class.getName()) : null);

            fieldValue = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            
            SubjectDnFieldData subjectDnFieldData = new SubjectDnFieldData.Builder(label, modifiable, required)
                    .withIsEmailAndUsesEmailFieldData(new MutablePair<>(isEmailAddress, required))
                    .withOptions(options)
                    .withValue(fieldValue)
                    .withRegex(regex)
                    .build();

            this.subjectDnFieldDatas.add(subjectDnFieldData);
        }
    }
    
    private void composeSubjectDirAttrFieldsAndData() {

        this.subjectDirAttrFieldDatas = new ArrayList<>();

        int numberOfSubjectDirAttrFields = selectedEeProfile.getSubjectDirAttrFieldOrderLength();

        for (int i = 0; i < numberOfSubjectDirAttrFields; i++) {
            int[] fieldData = selectedEeProfile.getSubjectDirAttrFieldsInOrder(i);

            final boolean modifiable = selectedEeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean required = selectedEeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
            final String fieldValue = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final String[] options = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                    .split(EndEntityProfile.SPLITCHAR);

            SubjectDirAttrFieldData subjectDirAttrFieldData = new SubjectDirAttrFieldData.Builder(label, modifiable, required)
                    .withFieldValue(fieldValue).withOptions(options).build();
            this.subjectDirAttrFieldDatas.add(subjectDirAttrFieldData);
        }
    }

    
    private UserView checkAndSetExtendedInformation(UserView newUserView) {
        if (getExtensionData() != null) {
            ExtendedInformation ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
                newUserView.setExtendedInformation(ei);
            }

            // Save the new value if the profile allows it
            if (selectedEeProfile.getUseExtensiondata()) {
                super.setExtensionData(getExtensionData());
            }
        }
        return newUserView;
    }

    private boolean doesPasswordAndConfirmationMatch() {
        if (!selectedEeProfile.useAutoGeneratedPasswd() && selectedEeProfile.isPasswordModifiable()) {
            return confirmPasswordFieldValue.equals(passwordFieldValue);
        } else {
            return true;
        }
    }

    private UserView checkAndSetNameConstraints(UserView newUserView) throws CertificateExtensionException {
        try {
            ExtendedInformation ei;
            if (selectedEeProfile.isNameConstraintsPermittedUsed()) {
                ei = newUserView.getExtendedInformation();
                if (ei == null) {
                    ei = new ExtendedInformation();
                }
                if (nameConstraintsPermitted != null && !nameConstraintsPermitted.trim().isEmpty()) {
                    ei.setNameConstraintsPermitted(NameConstraint.parseNameConstraintsList(nameConstraintsPermitted));
                } else {
                    ei.setNameConstraintsPermitted(null);
                }
                newUserView.setExtendedInformation(ei);
            }
            if (selectedEeProfile.isNameConstraintsExcludedUsed()) {
                ei = newUserView.getExtendedInformation();
                if (ei == null) {
                    ei = new ExtendedInformation();
                }
                if (nameConstraintsExcluded != null && !nameConstraintsExcluded.trim().isEmpty()) {
                    ei.setNameConstraintsExcluded(NameConstraint.parseNameConstraintsList(nameConstraintsExcluded));
                } else {
                    ei.setNameConstraintsExcluded(null);
                }
                newUserView.setExtendedInformation(ei);
            }
        } catch (CertificateExtensionException e) {
            addNonTranslatedErrorMessage(e.getMessage());
            throw e;
        }
        return newUserView;
    }

    private void finallyCreateUser(UserView newUserView) throws EndEntityExistsException, CADoesntExistsException, CertificateSerialNumberException,
            AuthorizationDeniedException, EndEntityProfileValidationException, IllegalNameException {
        // See if user already exists
        if (raBean.userExist(newUserView.getUsername())) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("ENDENTITYALREADYEXISTS"));
        } else {
            // No validation error. Go ahead an try to add user
            try {
                EndEntityInformation endEntityInformation = raBean.addUser(newUserView);
                newUserView.setUsername(endEntityInformation.getUsername());
                selectedEeProfile.setUsernameDefault(endEntityInformation.getUsername());
                final String addedUsername = endEntityInformation.getUsername();
                addNonTranslatedInfoMessage(
                        getEjbcaWebBean().getText("ENDENTITY") + " " + addedUsername + " " + getEjbcaWebBean().getText("ADDEDSUCCESSFULLY"));
            } catch (ApprovalException e) {
                handleApprovalException(e);
            } catch (WaitingForApprovalException e) {
                handleWaitingForApprovalException(e);
            } catch (EjbcaException e) {
                handleEjbcaException(e);
            } catch (IllegalNameException e) {
                handleIllegalNameException(e);
            } catch (EndEntityProfileValidationException | EJBException e) {
                addNonTranslatedErrorMessage(e.getMessage());
            } 
        }
    }

    private void handleIllegalNameException(IllegalNameException e) throws IllegalNameException {
        if (e.getErrorCode().equals(ErrorCode.NAMECONSTRAINT_VIOLATION)) {
            addNonTranslatedErrorMessage(e.getMessage());
        } else {
            throw e;
        }
    }

    private void handleEjbcaException(EjbcaException e) {
        if (e.getErrorCode().equals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS)) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("SERIALNUMBERALREADYEXISTS"));
        }
        if (e.getErrorCode().equals(ErrorCode.CA_NOT_EXISTS)) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CADOESNTEXIST"));
        }
        if (e.getErrorCode().equals(ErrorCode.FIELD_VALUE_NOT_VALID)) {
            addNonTranslatedErrorMessage(e.getMessage());
        }
        if (e.getErrorCode().equals(ErrorCode.NAMECONSTRAINT_VIOLATION)) {
            addNonTranslatedErrorMessage(e.getMessage());
        }        
    }

    private void handleWaitingForApprovalException(WaitingForApprovalException e) {
        addNonTranslatedErrorMessage(getEjbcaWebBean().getText("REQHAVEBEENADDEDFORAPPR"));
    }

    private void handleApprovalException(ApprovalException e) {
        if (e.getErrorCode().equals(ErrorCode.VALIDATION_FAILED)) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("DOMAINBLACKLISTVALIDATOR_VALIDATION_FAILED"));
        } else {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("THEREALREADYEXISTSAPPROVAL"));
        }        
    }

    private UserView checkAndSetCabfOrgId(UserView newUserView) throws ParameterException {
        if (selectedEeProfile.isCabfOrganizationIdentifierUsed()) {
            ExtendedInformation ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            String fieldValue = StringUtils.trim(cabfOrganizationIdentifier);
            if (selectedEeProfile.isCabfOrganizationIdentifierRequired() && StringUtils.isEmpty(fieldValue)) {
                throw new ParameterException(getEjbcaWebBean().getText("EXT_CABF_ORGANIZATION_IDENTIFIER_REQUIRED"));
            } else if (fieldValue != null && !fieldValue.matches(CabForumOrganizationIdentifier.VALIDATION_REGEX)) {
                throw new ParameterException(getEjbcaWebBean().getText("EXT_CABF_ORGANIZATION_IDENTIFIER_BADFORMAT"));
            }
            ei.setCabfOrganizationIdentifier(fieldValue);
            newUserView.setExtendedInformation(ei);
        }
        return newUserView;
    }

    private UserView checkAndSetPsd2QcStatement(UserView newUserView) {
        if (selectedEeProfile.isPsd2QcStatementUsed()) {
            ExtendedInformation ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            if (psd2NcaName != null && psd2NcaName.length() > 0) {
                ei.setQCEtsiPSD2NcaName(psd2NcaName.trim());
            }
            if (psd2NcaId != null && psd2NcaId.length() > 0) {
                ei.setQCEtsiPSD2NcaId(psd2NcaId.trim());
            }
            if (psd2PspRoles != null && !psd2PspRoles.isEmpty()) {
                final List<PSD2RoleOfPSPStatement> pspRoles = new ArrayList<>();
                for (String role : psd2PspRoles) {
                    pspRoles.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid(role), role));
                }
                ei.setQCEtsiPSD2RolesOfPSP(pspRoles);
            }
            newUserView.setExtendedInformation(ei);
        }
        return newUserView;
    }

    private UserView checkAndSetCustomSerialNumber(UserView newUserView) throws EndEntityException {
        if (selectedEeProfile.isCustomSerialNumberUsed()) {
            ExtendedInformation ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            if (customSerialNumber != null && customSerialNumber.length() > 0) {
                try {
                    ei.setCertificateSerialNumber(new BigInteger(customSerialNumber.trim(), 16));
                } catch (NumberFormatException e) {
                    throw new EndEntityException("Number format exception " + e.getMessage());
                }
            } else {
                ei.setCertificateSerialNumber(null);
            }
            newUserView.setExtendedInformation(ei);
        }
        return newUserView;
    }

    private UserView checkAndSetValidityTimes(UserView newUserView) throws ParseException {
        ExtendedInformation ei;
        if (selectedEeProfile.isValidityStartTimeUsed() && (validityStartTimeValue != null && (validityStartTimeValue.trim().length() > 0))) {
            String storeValue = getEjbcaWebBean().getImpliedUTCFromISO8601OrRelative(validityStartTimeValue.trim());
            ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, storeValue);
            newUserView.setExtendedInformation(ei);
            selectedEeProfile.setValidityStartTime(validityStartTimeValue.trim());
        }

        if (selectedEeProfile.isValidityEndTimeUsed() && (validityEndTimeValue != null && (validityEndTimeValue.trim().length() > 0))) {
            String storeValue = getEjbcaWebBean().getImpliedUTCFromISO8601OrRelative(validityEndTimeValue.trim());
            ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, storeValue);
            newUserView.setExtendedInformation(ei);
            selectedEeProfile.setValidityEndTime(validityEndTimeValue.trim());
        }
        return newUserView;
    }

    private UserView checkAndSetMainCertificateData(UserView newUserView) throws EndEntityException {
        /*  Main Certificate Data   */
        
        if (selectedCertProfileId == -1) {
            throw new EndEntityException(getEjbcaWebBean().getText("CERTIFICATEPROFILEMUST"));
        }
        
        if (selectedCaId == -1) {
            throw new EndEntityException(getEjbcaWebBean().getText("CAMUST"));
        }
        
        if (selectedTokenId == -1) {
            throw new EndEntityException(getEjbcaWebBean().getText("TOKENMUST"));
        }
        
        newUserView.setCertificateProfileId(selectedCertProfileId);
        newUserView.setCAId(selectedCaId);
        newUserView.setTokenType(selectedTokenId);
        return newUserView;
    }

    private UserView checkAndSetRevokationReason(UserView newUserView) {
        // Issuance revocation reason, what state a newly issued certificate will have
        if (selectedEeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)) {
            String fieldValue = String.valueOf(revocationStatus);
            // If it's not modifyable don't even try to modify it
            if (!selectedEeProfile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)) {
                fieldValue = selectedEeProfile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
            }
            if (fieldValue != null) {
                ExtendedInformation ei = newUserView.getExtendedInformation();
                if (ei == null) {
                    ei = new ExtendedInformation();
                }
                ei.setCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON, fieldValue);
                newUserView.setExtendedInformation(ei);
                selectedEeProfile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, fieldValue);
            } else {
                selectedEeProfile.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, "" + RevokedCertInfo.NOT_REVOKED);
            }
        }
        return newUserView;
    }

    private UserView checkAndSetMaxNumberOfRequests(UserView newUserView) {
        if (selectedEeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0)) {
            ExtendedInformation ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
            }
            ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(numberOfRequests));
            newUserView.setExtendedInformation(ei);
        }
        return newUserView;
    }

    private UserView checkAndSetSubjectDirName(UserView newUserView) throws EndEntityException {

        StringBuilder subjectDirAttr = new StringBuilder();
        
        int i = 0;
        for (SubjectDirAttrFieldData subjectDirAttrFieldAndData : getSubjectDirAttrFieldDatas()) {
            int[] fieldData = selectedEeProfile.getSubjectDirAttrFieldsInOrder(i++);
            String fieldValue = subjectDirAttrFieldAndData.getFieldValueToSave(newUserView, fieldData);
            
            if (StringUtils.isNotBlank(fieldValue)) {
                if(!certProfileSession.getCertificateProfile(selectedCertProfileId).getUseSubjectDirAttributes()) {
                    throw new EndEntityException("Usage of subject dir attributes is not allowed in the selected certificate profile.");
                }
                fieldValue = fieldValue.trim();
                fieldValue = LDAPDN.escapeRDN(DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                        DNFieldExtractor.TYPE_SUBJECTDIRATTR) + fieldValue);
                if (subjectDirAttr.length() == 0) {
                    subjectDirAttr.append(fieldValue);
                } else {
                    subjectDirAttr.append(", " + fieldValue);
                }
            }
        }
        
        newUserView.setSubjectDirAttributes(subjectDirAttr.toString());
        return newUserView;
    }

    private UserView checkAndSetSubjectAltName(UserView newUserView) throws EndEntityException {

        StringBuilder subjectAltName = new StringBuilder();
        int i = 0;
        String fieldValue;
        for (final SubjectAltNameFieldData subjectAltNameFieldAndData : getSubjectAltNameFieldDatas()) {
            int[] fieldData = selectedEeProfile.getSubjectAltNameFieldsInOrder(i++);
            
            if(subjectAltNameFieldAndData.isCopyDataFromCN()) {
                fieldValue = handleCopyFromCN(subjectAltNameFieldAndData, fieldData);
            } else  {
                fieldValue = subjectAltNameFieldAndData.getFieldValueToSave(newUserView, fieldData);
            }

            if (StringUtils.isNotBlank(fieldValue)) {
                if(!certProfileSession.getCertificateProfile(selectedCertProfileId).getUseSubjectAlternativeName()) {
                    throw new EndEntityException("Usage of subject alternative name is not allowed in the selected certificate profile.");
                }
                if (subjectAltName.length() == 0) {
                    subjectAltName.append(fieldValue);
                } else {
                    subjectAltName.append(", " + fieldValue);
                }
            }
        }
        newUserView.setSubjectAltName(subjectAltName.toString());
        return newUserView;
    }
    
    private String handleCopyFromCN(final SubjectAltNameFieldData subjectAltNameFieldAndData, final int[] fieldData) throws EndEntityException {

        String resutlFieldValue = StringUtils.EMPTY;

        if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNSNAME)) {
            resutlFieldValue = handleCopyFromCnDns();
        } else if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
            resutlFieldValue = handleCopyFromCnUpn(subjectAltNameFieldAndData, selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]));
        } 
        
        if (StringUtils.isNotBlank(resutlFieldValue)) {
            resutlFieldValue = org.ietf.ldap.LDAPDN
                    .escapeRDN(DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                            DNFieldExtractor.TYPE_SUBJECTALTNAME) + resutlFieldValue);
        }
        return resutlFieldValue;
    }

    private String handleCopyFromCnUpn(SubjectAltNameFieldData subjectAltNameFieldAndData, String upnFromProfile) throws EndEntityException {

        String resutlFieldValue = StringUtils.EMPTY;
        String valueFromCN;
        String upnUserName = subjectAltNameFieldAndData.getUpnName();
        String upnDomain = subjectAltNameFieldAndData.getUpnDomain();

        int i = 0;
        for (SubjectDnFieldData dnFieldData : getSubjectDnFieldsAndDatas()) {
            int[] sDNfieldData = selectedEeProfile.getSubjectDNFieldsInOrder(i++);
            if (EndEntityProfile.isFieldOfType(sDNfieldData[EndEntityProfile.FIELDTYPE], DnComponents.COMMONNAME)) {
                valueFromCN = dnFieldData.getFieldValue();
                if (StringUtils.isNotBlank(valueFromCN) && StringUtils.isNotBlank(upnFromProfile)) {
                    resutlFieldValue = valueFromCN + "@" + upnFromProfile;
                } 
                break;
            } 
        }
        
        if (StringUtils.isBlank(resutlFieldValue) &&  StringUtils.isNotBlank(upnUserName)) {
            resutlFieldValue = upnUserName + "@" + upnDomain;
        }
        return resutlFieldValue;
    }

    private String handleCopyFromCnDns() {
        String resutlFieldValue = StringUtils.EMPTY;
        int i = 0;
        for (SubjectDnFieldData dnFieldData : getSubjectDnFieldsAndDatas()) {
            int[] sDNfieldData = selectedEeProfile.getSubjectDNFieldsInOrder(i++);

            if (EndEntityProfile.isFieldOfType(sDNfieldData[EndEntityProfile.FIELDTYPE], DnComponents.COMMONNAME)
                    && StringUtils.isNotBlank(dnFieldData.getFieldValue())) {
                resutlFieldValue = dnFieldData.getFieldValue();
                break;
            }
        }
        return resutlFieldValue;
    }

    private UserView checkAndSetSubjectDN(UserView newUserView) throws EndEntityException {
        StringBuilder subjectDn = new StringBuilder();
        int i = 0;
        for (SubjectDnFieldData subjectDnFieldAndData : getSubjectDnFieldsAndDatas()) {
            String value = null;
            int[] fieldData = selectedEeProfile.getSubjectDNFieldsInOrder(i++);

            if (subjectDnFieldAndData.getIsEmailAndUsesEmailFieldData().getLeft() && subjectDnFieldAndData.getIsEmailAndUsesEmailFieldData().getRight()) {
                value = newUserView.getEmail();
            } else {
                value = subjectDnFieldAndData.getFieldValue();
                subjectDnFieldAndData.validateFieldValue(value, fieldData);
            }
            
            if (StringUtils.isNotBlank(value)) {
                value = value.trim();

                final String fieldComp = DNFieldExtractor.getFieldComponent(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                        DNFieldExtractor.TYPE_SUBJECTDN) + value;
                final String dnPart;
                if (fieldComp.charAt(fieldComp.length() - 1) != '=') {
                    dnPart = LDAPDN.escapeRDN(fieldComp);
                } else {
                    dnPart = fieldComp;
                }
                if (subjectDn.length() == 0) {
                    subjectDn.append(dnPart);
                } else {
                    subjectDn.append(", " + dnPart);
                }
                continue;
            }
            
            if (subjectDnFieldAndData.getOptions().length >=1 && StringUtils.isNotBlank(subjectDnFieldAndData.getFieldValue())) {
                value = subjectDnFieldAndData.getFieldValueToSave(newUserView, fieldData);
                if (StringUtils.isNotEmpty(value)) {

                    if (subjectDn.length() == 0) {
                        subjectDn.append(value);
                    }
                    else {
                        subjectDn.append(", " + value);
                    }
                }
            }
        }
        newUserView.setSubjectDN(subjectDn.toString());
        return newUserView;
    }

    private UserView checkAndSetCardNumber(UserView newUserView) {
        if (getCardNumber() != null) {
            final String cardNum = getCardNumber().trim();
            if (StringUtils.isNotBlank(cardNum)) {
                newUserView.setCardNumber(cardNum);
            }
        }
        return newUserView;
    }

    private Optional<UserView> checkAndSetUserEmail(UserView newUserView) throws EndEntityException {
        if (StringUtils.isNotBlank(emailUserName)) {
            if (handleEmailUserNameNotEmpty(newUserView).isPresent()) {
                return Optional.of(handleEmailUserNameNotEmpty(newUserView).get());
            } else {
                return Optional.empty();
            }
        } else {
            handleEmailUserNameEmpty();
        }
        return Optional.of(newUserView);
    }

    private void handleEmailUserNameEmpty() throws EndEntityException {
        String selectedeEmailDomain = getEmailDomain();
        if (StringUtils.isNotBlank(selectedeEmailDomain) && selectedEeProfile.isEmailRequired()) { // We have a domain but no username, so email incomplete!
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
            throw new EndEntityException(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
        }
    }

    private Optional<UserView> handleEmailUserNameNotEmpty(UserView newUserView) throws EndEntityException {
        if (StringUtils.isNotBlank(emailDomain)) {
            if (!AddEndEntityUtil.isValidEmail(emailUserName + "@" + emailDomain.trim())) {
                throw new EndEntityException(getEjbcaWebBean().getText("ONLYEMAILCHARSNOAT") + " Email.");
            }
            newUserView.setEmail(emailUserName + "@" + emailDomain.trim());
        } else {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
            return Optional.empty();
        }

        return Optional.of(newUserView);
    }

    private UserView checkAndSetLoginAttempts(UserView newUserView) throws EndEntityException {
        ExtendedInformation ei = newUserView.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation();
        }

        if (StringUtils.isNotBlank(getMaxLoginAttempts())) {
            try {
                Integer.parseInt(getMaxLoginAttempts());
            } catch (NumberFormatException e) {
                throw new EndEntityException("Malformed number for max login attempts!");
            }
            ei.setMaxLoginAttempts(Integer.parseInt(getMaxLoginAttempts()));
            ei.setRemainingLoginAttempts(Integer.parseInt(getMaxLoginAttempts()));
            newUserView.setExtendedInformation(ei);
        }

        return newUserView;
    }

    private UserView checkAndSetUserNameAndPassword(final UserView newUserView) throws EndEntityException {
        if (getExtensionData() != null) {
            ExtendedInformation ei = newUserView.getExtendedInformation();
            if (ei == null) {
                ei = new ExtendedInformation();
                newUserView.setExtendedInformation(ei);
            }
        }

        if (StringUtils.isNotBlank(getUserName())) {
            if(!selectedEeProfile.isAutoGeneratedUsername() && !AddEndEntityUtil.isValidUserNameField(getUserName())) {
                throw new EndEntityException(getEjbcaWebBean().getText("ONLYCHARACTERS") + " " + getEjbcaWebBean().getText("USERNAME"));
            }
            
            newUserView.setUsername(getUserName().trim());
        }
        
        if (StringUtils.isNotBlank(getPasswordFieldValue())) {
            newUserView.setPassword(getPasswordFieldValue().trim());
        }

        if (!isClearTextPasswordRequired()) {
            newUserView.setClearTextPassword(isUseClearTextPasswordStorage());
        } else {
            //We end up here if the checkbox was non-modifiable. 
            newUserView.setClearTextPassword(selectedEeProfile.getValue(EndEntityProfile.CLEARTEXTPASSWORD, 0).equals(EndEntityProfile.TRUE));
        }        
        
        return newUserView;
    }
    
}
