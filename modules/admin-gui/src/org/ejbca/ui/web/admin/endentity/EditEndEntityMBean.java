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

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.log4j.Logger;
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
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.SecConst;
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
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.faces.context.FacesContext;
import jakarta.faces.event.AjaxBehaviorEvent;
import jakarta.faces.model.SelectItem;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;

@Named
@ViewScoped
public class EditEndEntityMBean extends EndEntityBaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private static final Logger log = Logger.getLogger(EditEndEntityMBean.class);

    
    private static final String USER_PARAMETER = "username";

    private String userName = null;
    private String eePassword = null;
    private String eeConfirmPassword = null;
    private String selectedPassword = null;
    private List<String> selectPasswordList = new ArrayList<>();

    private String maxLoginAttempts = StringUtils.EMPTY;
    private String maxLoginAttemptsStatus;
    private boolean resetMaxLoginAttempts;
    private boolean useClearTextPasswordStorage;

    private String emailName = StringUtils.EMPTY;
    private String emailDomain = StringUtils.EMPTY;

    private String[] emailOptions = null;

    private EndEntityProfile eeProfile = null;

    private List<SubjectDnFieldData> subjectDnFieldDatas;
    private List<SubjectAltNameFieldData> subjectAltNameFieldDatas;
    private List<SubjectDirAttrFieldData> subjectDirAttrFieldDatas;

    /* Main Certificate Data */
    private int selectedCertProfileId = -1;
    private int selectedTokenId = -1;
    private int selectedCaId = -1;

    private int selectedEeProfileId = EndEntityConstants.NO_END_ENTITY_PROFILE;

    boolean userchanged = false;
    boolean nouserparameter = true;
    boolean notauthorized = true;
    boolean endentitysaved = false;
    private String[] eeProfileNames = null;
    private int eeStatus;
    private boolean regeneratePassword;
    private String customSerialNumber;

    private String validityStartTime = StringUtils.EMPTY;
    private String validityEndTime = StringUtils.EMPTY;
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
    private MutablePair<Boolean, Boolean> keyRecoveryCheckboxStatus = new MutablePair<>();


    String approvalmessage = null;

    private EjbcaWebBean ejbcaWebBean;
    private RAInterfaceBean raBean;
    GlobalConfiguration globalConfiguration = null;

    @EJB
    CaSessionLocal caSession;

    @EJB
    private AuthorizationSessionLocal authorizationSession;

    @EJB
    private CertificateProfileSessionLocal certProfileSession;

    // Authentication check and audit log page access request
    @PostConstruct
    public void initialize() throws EndEntityException {

        try {
            if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR)) {
                throw new AuthorizationDeniedException("You are not authorized to view this page.");
            }

            initializeBaseData();

        } catch (Exception e) {
            throw new EndEntityException("Error while initializing the class " + this.getClass().getCanonicalName(), e);
        }

    }

    private void initializeBaseData() throws Exception {
        try {
            initData();
        } catch (Exception e) {
            addNonTranslatedErrorMessage(e.getMessage());
            throw e;
        }
    }

    // Initialize environment.
    private void initData() throws Exception {
        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        
        userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER), StandardCharsets.UTF_8);
        ejbcaWebBean = getEjbcaWebBean();
        raBean = SessionBeans.getRaBean(request);
        raBean.initialize(ejbcaWebBean);

        RequestHelper.setDefaultCharacterEncoding(request);

        eeProfileNames = (String[]) ejbcaWebBean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.EDIT_END_ENTITY).keySet()
                .toArray(new String[0]);

        globalConfiguration = ejbcaWebBean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR,
                AccessRulesConstants.REGULAR_EDITENDENTITY);

        initializeData();

    }
    
    private void initializeData() throws EndEntityException, EndEntityProfileNotFoundException, AuthorizationDeniedException {
        if (eeProfileNames == null || eeProfileNames.length == 0) {
            throw new EndEntityException(getEjbcaWebBean().getText("NOTAUTHORIZEDTOCREATEENDENTITY"));
        } else {
            this.setSelectedEeProfileId(raBean.getEndEntityProfileId(eeProfileNames[0]));
            this.eeProfile = raBean.getEndEntityProfile(selectedEeProfileId);
        }

        if (StringUtils.isNotBlank(userName)) {
            userData = raBean.findUserForEdit(userName);

            if (userData != null) {
                eeStatus = userData.getStatus();
                selectedEeProfileId = userData.getEndEntityProfileId();
                eeProfile = raBean.getEndEntityProfile(selectedEeProfileId);
                
                initTheRest();
                updateMainCertDataSection();
                
            } else {
                throw new EndEntityException(ejbcaWebBean.getText("ENDENTITYDOESNTEXIST"));
            }

        } else {
            throw new EndEntityException(ejbcaWebBean.getText("YOUMUSTSPECIFYUSERNAME"));
        }
        
        initSubjectData();


    }

    private void initSubjectData() {
        composeSubjectDnFieldsAndData();
        composeSubjectAltNameFieldAndData();
        composeSubjectDirAttrFieldsAndData();
    }

    private void initTheRest() {
        useClearTextPasswordStorage = (eeProfile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0) || userData.getClearTextPassword());

        ExtendedInformation maxei = userData.getExtendedInformation();
        if (maxei != null) {
            maxLoginAttempts = String.valueOf(maxei.getMaxLoginAttempts());
        }


        maxLoginAttemptsStatus = maxLoginAttempts.equals("-1") ? "unlimited" : "specified";

        if (eeProfile.getUse(EndEntityProfile.EMAIL, 0) && (userData.getEmail() != null && !userData.getEmail().equals(StringUtils.EMPTY))) {
            emailName = userData.getEmail().substring(0, userData.getEmail().indexOf('@'));
            emailDomain = userData.getEmail().substring(userData.getEmail().indexOf('@') + 1);

        }

        if(!eeProfile.isModifyable(EndEntityProfile.EMAIL,0)){
            emailOptions = eeProfile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
        }
        
        this.keyRecoveryCheckboxStatus.setLeft(userData.getKeyRecoverable());
        this.keyRecoveryCheckboxStatus.setRight(eeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE, 0));

        if (eeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0)) {
            String defaultnrofrequests = eeProfile.getValue(EndEntityProfile.ALLOWEDREQUESTS, 0);
            if (defaultnrofrequests == null) {
                defaultnrofrequests = "1";
            }
            ExtendedInformation ei = userData.getExtendedInformation();
            String counter = ei != null ? ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER) : null;
            if (counter == null) {
                counter = defaultnrofrequests;
            }

            this.numberOfRequests = Integer.parseInt(counter);
        }

        if (eeProfile.getPredefinedPassword() != null) {
            selectedPassword = eeProfile.getPredefinedPassword().trim();
            selectPasswordList.add(eeProfile.getPredefinedPassword().trim());
        }
        
    }
    
    private void updateMainCertDataSection() {
        /* Main Certificate Data */
        this.selectedCertProfileId = userData.getCertificateProfileId();
        this.selectedCaId = userData.getCAId();
        this.selectedTokenId = userData.getTokenType();
        this.useKeyRecovery = globalConfiguration.getEnableKeyRecovery() && eeProfile.getUse(EndEntityProfile.KEYRECOVERABLE, 0);
    }

    public String actionChangeEndEntityProfile(AjaxBehaviorEvent event) throws Exception {
        
        eeProfileNames = (String[]) ejbcaWebBean.getAuthorizedEndEntityProfileNames(AccessRulesConstants.EDIT_END_ENTITY).keySet()
                .toArray(new String[0]);
        
        eeProfile = raBean.getEndEntityProfile(selectedEeProfileId);
        selectedCertProfileId = eeProfile.getDefaultCertificateProfile();
        userData.setEndEntityProfileId(selectedEeProfileId);
        initTheRest();
        initSubjectData();
        return "editendentity";
    }

    public String getRemainingLoginAttemps() {
        if ((userData.getExtendedInformation() != null) && (userData.getExtendedInformation().getRemainingLoginAttempts() != -1)) {
            return String.valueOf(userData.getExtendedInformation().getRemainingLoginAttempts());
        } else {
            return StringUtils.EMPTY;
        }
    }

    public boolean isMaxFailedLoginAttemptsModifiable() {
        return eeProfile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS, 0);
    }

    public List<SubjectDnFieldData> getSubjectDnFieldsAndDatas() {
        return subjectDnFieldDatas;
    }

    public String getEeConfirmPassword() {
        return eeConfirmPassword;
    }

    public void setEeConfirmPassword(String eeConfirmPassword) {
        this.eeConfirmPassword = eeConfirmPassword;
    }

    public List<SelectItem> getSelectPasswordList() {
        List<SelectItem> result = new ArrayList<>();

        if (eeProfile.getPredefinedPassword() != null) {
            result.add(new SelectItem(eeProfile.getPredefinedPassword().trim(), eeProfile.getPredefinedPassword().trim()));
        }
        return result;
    }

    public boolean isProfileHasSubjectAltNameFields() {
        return eeProfile.getSubjectAltNameFieldOrderLength() > 0;
    }

    public boolean isProfileHasSubjectDirAttrFields() {
        return eeProfile.getSubjectDirAttrFieldOrderLength() > 0;
    }

    public boolean isPasswordReGenRequired() {
        return ((eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY) && eeStatus != userData.getStatus()
                && !regeneratePassword && selectedTokenId <= SecConst.TOKEN_SOFT);
    }

    public String getEePassword() {
        return eePassword;
    }

    public void setEePassword(String eePassword) {
        this.eePassword = eePassword;
    }

    public boolean isUseAutoGeneratedPasswd() {
        return eeProfile.useAutoGeneratedPasswd();
    }

    public boolean isPasswordModifiable() {
        return eeProfile.isPasswordModifiable();
    }

    public boolean isPredefinedPasswordNotNull() {
        return eeProfile.getPredefinedPassword() != null;
    }
    
    public boolean isPasswordRequired() {
        if (!eeProfile.useAutoGeneratedPasswd()) {
            if (eeProfile.isPasswordModifiable()) {
                if ((eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY)
                        && eeStatus != userData.getStatus() && eePassword.equals(StringUtils.EMPTY)) {
                    return true;
                }

            } else {
                if ((eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY)
                        && eeStatus != userData.getStatus() && selectedPassword == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isUserNameHasRegex() {
        return eeProfile.getUseValidationForUsername();
    }

    public String getUserNameRegex() {
        return eeProfile.getUsernameDefaultValidation();
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public boolean isAllowedToEditEndEntity() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITENDENTITY);
    }

    public List<SelectItem> getAvailableEndEntityProfiles() throws EndEntityProfileNotFoundException {
        final List<SelectItem> ret = new ArrayList<>();
        for (int i = 0; i < eeProfileNames.length; i++) {
            int pId = raBean.getEndEntityProfileId(eeProfileNames[i]);
            ret.add(new SelectItem(pId, eeProfileNames[i]));

        }
        return ret;
    }

    public List<SelectItem> getAvailableEeStatus() {
        final List<SelectItem> ret = new ArrayList<>();

        if (userData.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) {
            ret.add(new SelectItem(EndEntityConstants.STATUS_KEYRECOVERY, ejbcaWebBean.getText("STATUSKEYRECOVERY")));

        }         
        
        ret.add(new SelectItem(EndEntityConstants.STATUS_NEW, ejbcaWebBean.getText("STATUSNEW")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_FAILED, ejbcaWebBean.getText("STATUSFAILED")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_INITIALIZED, ejbcaWebBean.getText("STATUSINITIALIZED")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_INPROCESS, ejbcaWebBean.getText("STATUSINPROCESS")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_GENERATED, ejbcaWebBean.getText("STATUSGENERATED")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_REVOKED, ejbcaWebBean.getText("STATUSREVOKED")));
        ret.add(new SelectItem(EndEntityConstants.STATUS_HISTORICAL, ejbcaWebBean.getText("STATUSHISTORICAL")));

        return ret;

    }

    public int getSelectedEeProfileId() {
        return selectedEeProfileId;
    }

    public void setSelectedEeProfileId(int selectedEeProfileId) {
        this.selectedEeProfileId = selectedEeProfileId;
    }

    public int getEeStatus() {
        return eeStatus;
    }

    public void setEeStatus(int eeStatus) {
        this.eeStatus = eeStatus;
    }

    public boolean isRegeneratePassword() {
        return regeneratePassword;
    }

    public void setRegeneratePassword(boolean regeneratePassword) {
        this.regeneratePassword = regeneratePassword;
    }

    public String getMaxLoginAttempts() {
        if (maxLoginAttempts.equals("-1")) {
            return StringUtils.EMPTY;
        } 
        return maxLoginAttempts;
    }

    public void setMaxLoginAttempts(String maxLoginAttempts) {
        this.maxLoginAttempts = maxLoginAttempts;
    }

    public String getMaxLoginAttemptsStatus() {
        return maxLoginAttemptsStatus;
    }

    public void setMaxLoginAttemptsStatus(String maxLoginAttemptsStatus) {
        this.maxLoginAttemptsStatus = maxLoginAttemptsStatus;
    }

    public boolean isResetMaxLoginAttempts() {
        return resetMaxLoginAttempts;
    }

    public void setResetMaxLoginAttempts(boolean resetMaxLoginAttempts) {
        this.resetMaxLoginAttempts = resetMaxLoginAttempts;
    }
    
    public String getRemainingLoginAttempts() {
        if((userData.getExtendedInformation() != null) && (userData.getExtendedInformation().getRemainingLoginAttempts() != -1)) {
            return String.valueOf(userData.getExtendedInformation().getRemainingLoginAttempts());
        }
        return StringUtils.EMPTY;
    }
    

    public boolean isUseBatchGenerationPassword() {
        return eeProfile.getUse(EndEntityProfile.CLEARTEXTPASSWORD, 0);
    }

    public boolean isUseClearTextPasswordStorage() {
        return useClearTextPasswordStorage;
    }

    public void setUseClearTextPasswordStorage(boolean useClearTextPasswordStorage) {
        this.useClearTextPasswordStorage = useClearTextPasswordStorage;
    }

    public boolean isRequiredClearTextPasswordStorage() {
        return eeProfile.isRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0);
    }

    public String getEmailName() {
        return emailName;
    }

    public void setEmailName(String emailName) {
        this.emailName = emailName;
    }

    public String getEmailDomain() {
        return emailDomain;
    }

    public void setEmailDomain(String emailDomain) {
        this.emailDomain = emailDomain;
    }

    public boolean isEmailModifiable() {
        return eeProfile.isModifyable(EndEntityProfile.EMAIL, 0);
    }

    public String[] getEmailOptions() {
        return emailOptions;
    }

    public boolean isEmailRequired() {
        return eeProfile.isRequired(EndEntityProfile.EMAIL, 0);
    }
    
    public boolean isUseEmail() {
        return eeProfile.getUse(EndEntityProfile.EMAIL,0);
    }

    private void composeSubjectDnFieldsAndData() {

        this.subjectDnFieldDatas = new ArrayList<>();

        int numberOfSubjectDnFields = eeProfile.getSubjectDNFieldOrderLength();

        for (int i = 0; i < numberOfSubjectDnFields; i++) {

            int[] fieldData = eeProfile.getSubjectDNFieldsInOrder(i);

            final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
            final boolean required = eeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean modifiable = eeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean isEmailAddress = EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS);

            String[] options = null;
            String regex = null;
            String fieldValue = null;

            options = eeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]).split(EndEntityProfile.SPLITCHAR);
            final Map<String, Serializable> validation = eeProfile.getValidation(fieldData[EndEntityProfile.FIELDTYPE],
                    fieldData[EndEntityProfile.NUMBER]);
            regex = (validation != null ? (String) validation.get(RegexFieldValidator.class.getName()) : null);

            fieldValue = userData.getSubjectDNField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                    fieldData[EndEntityProfile.NUMBER]);
            
            
            boolean isUseEmailFeildData = false;
            
            if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS) && (StringUtils
                    .isNotBlank(userData.getSubjectDNField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                            fieldData[EndEntityProfile.NUMBER]))
                    || eeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]))) {
                isUseEmailFeildData = true;
            }

            SubjectDnFieldData subjectDnFieldData = new SubjectDnFieldData.Builder(label, modifiable, required)
                    .withIsEmailAndUsesEmailFieldData(new MutablePair<>(isEmailAddress, isUseEmailFeildData)).withOptions(options).withValue(fieldValue)
                    .withRegex(regex).build();

            this.subjectDnFieldDatas.add(subjectDnFieldData);
        }
    }

    private void composeSubjectAltNameFieldAndData() {

        this.subjectAltNameFieldDatas = new ArrayList<>();

        final int numberOfSubjectAltNameFields = eeProfile.getSubjectAltNameFieldOrderLength();

        for (int i = 0; i < numberOfSubjectAltNameFields; i++) {

            final int[] fieldData = eeProfile.getSubjectAltNameFieldsInOrder(i);
            int fieldType = fieldData[EndEntityProfile.FIELDTYPE];

            final boolean modifiable = eeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean required = eeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean isRFC822Name = EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME);
            final boolean useDataFromEmailFieldCheckBoxValue = EndEntityProfile.isFieldOfType(fieldType, DnComponents.RFC822NAME) && eeProfile.getUse(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean copyDataFromCN = eeProfile.getCopy(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
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

            final boolean rfc822UseEmailField = EndEntityProfile.isFieldOfType(fieldType, DnComponents.RFC822NAME)
                    && eeProfile.getUse(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            if (!rfc822UseEmailField) {
                if ((EndEntityProfile.isFieldOfType(fieldType, DnComponents.UPN))
                        || (EndEntityProfile.isFieldOfType(fieldType, DnComponents.RFC822NAME))) {
                    String name = StringUtils.EMPTY;
                    String domain = StringUtils.EMPTY;
                    String fullName = userData.getSubjectAltNameField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                            fieldData[EndEntityProfile.NUMBER]);
                    if (fullName != null && !fullName.equals("")) {
                        // if we have an @ sign, we will assume it is name@domain, if we have no @ sign, 
                        // we will assume that the name has not been entered yet.
                        if (fullName.contains("@")) {
                            name = fullName.substring(0, fullName.indexOf('@'));
                            domain = fullName.substring(fullName.indexOf('@') + 1);
                        } else {
                            domain = fullName;
                        }
                    }

                    String profileValue = eeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                    // if the field is not modifyable, and the options contains an @ sign, we assume that the complete field is actually locked down
                    // and we should not attempt to split it in name@domain parts
                    if (!(!modifiable && profileValue.contains("@"))) {
                        if (EndEntityProfile.isFieldOfType(fieldType, DnComponents.UPN)) {
                            upnName = name;
                            upnDomain = domain;
                        } else {
                            rfcName = name;
                            rfcDomain = domain;
                        }
                    }
                    // Only display the domain part if we have not completely locked down the email address
                    if (!modifiable) {
                        options = profileValue.split(EndEntityProfile.SPLITCHAR);
                        if (options == null || options.length <= 0) {
                            // Do nothing

                        } else {
                            if (options.length == 1) {
                                rfcDomain = options[0].trim();
                            }
                        }
                    } else {
                        rfcDomain = domain;
                    }
                } else {
                    if (!eeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])) {
                        options = eeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                                .split(EndEntityProfile.SPLITCHAR);
                        if (options == null || options.length <= 0) {
                            // Do nothing

                        } else {
                            if (options.length == 1) {
                                rfcDomain = options[0].trim();
                            }
                        }
                    } else {
                        final Map<String, Serializable> validation = eeProfile.getValidation(fieldData[EndEntityProfile.FIELDTYPE],
                                fieldData[EndEntityProfile.NUMBER]);
                        regex = (validation != null ? (String) validation.get(RegexFieldValidator.class.getName()) : null);
                        fieldValue = userData.getSubjectAltNameField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                                fieldData[EndEntityProfile.NUMBER]);
                    }
                }
            }

            boolean isUseEmailField = false;
            
            if (EndEntityProfile.isFieldImplemented(fieldType)) {
                final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
                
                if (rfc822UseEmailField) {
                    isUseEmailField = StringUtils
                            .isNotBlank(userData.getSubjectAltNameField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                                    fieldData[EndEntityProfile.NUMBER]))
                            || eeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                }
                
                SubjectAltNameFieldData subjectAltNameFieldData = new SubjectAltNameFieldData.Builder(label, modifiable, required)
                        .withFieldValue(fieldValue).withRFC822Name(isRFC822Name).withUseDataFromRFC822NameField(isUseEmailField)
                        .withRenderDataFromRFC822CheckBox(useDataFromEmailFieldCheckBoxValue).withCopyDataFromCN(copyDataFromCN).withDNSName(isDnsName)
                        .withRfcName(rfcName).withRfcDomain(rfcDomain).withOptions(options).withRegex(regex).withRfc822NameString(rfc822NameString)
                        .withUpn(isUpn).withUpnName(upnName).withUpnDomain(upnDomain).build();
                subjectAltNameFieldDatas.add(subjectAltNameFieldData);
            }
        }
    }

    private void composeSubjectDirAttrFieldsAndData() {

        this.subjectDirAttrFieldDatas = new ArrayList<>();

        int numberOfSubjectDirAttrFields = eeProfile.getSubjectDirAttrFieldOrderLength();

        for (int i = 0; i < numberOfSubjectDirAttrFields; i++) {
            int[] fieldData = eeProfile.getSubjectDirAttrFieldsInOrder(i);

            final boolean modifiable = eeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final boolean required = eeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
            final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));

            final String fieldValue = userData.getSubjectDirAttributeField(DnComponents.profileIdToDnId(fieldData[EndEntityProfile.FIELDTYPE]),
                    fieldData[EndEntityProfile.NUMBER]);
            final String[] options = eeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                    .split(EndEntityProfile.SPLITCHAR);

            SubjectDirAttrFieldData subjectDirAttrFieldData = new SubjectDirAttrFieldData.Builder(label, modifiable, required)
                    .withFieldValue(fieldValue).withOptions(options).build();
            this.subjectDirAttrFieldDatas.add(subjectDirAttrFieldData);
        }
    }

    public List<SubjectAltNameFieldData> getSubjectAltNameFieldDatas() {
        return subjectAltNameFieldDatas;
    }

    public List<SubjectDirAttrFieldData> getSubjectDirAttrFieldDatas() {
        return subjectDirAttrFieldDatas;
    }

    public List<SelectItem> getAvailableCertProfiles() {
        List<SelectItem> profiles = new ArrayList<>();
        
        String[] availableCertProfileIds = eeProfile.getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);

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

    public int getSelectedTokenId() {
        return selectedTokenId;
    }

    public void setSelectedTokenId(int selectedTokenId) {
        this.selectedTokenId = selectedTokenId;
    }

    public int getSelectedCaId() {
        return selectedCaId;
    }

    public void setSelectedCaId(int selectedCaId) {
        this.selectedCaId = selectedCaId;
    }

    public List<SelectItem> getAvailableCas() {
        
        Map<Integer, List<Integer>> currentAvailableCas = raBean.getCasAvailableToEndEntity(selectedEeProfileId);
        List<SelectItem> availableCasList = new ArrayList<>();
        List<Integer> availableCasToSelectedCertProfile = currentAvailableCas.get(selectedCertProfileId);
        
        Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();

        if (Objects.nonNull(availableCasToSelectedCertProfile)) {
            for (final int caId : availableCasToSelectedCertProfile) {
                availableCasList.add(new SelectItem(caId, caIdToNameMap.get(caId)));
            }
        }

        return availableCasList;
    }

    public List<SelectItem> getAvailableTokens() {

        List<SelectItem> listOfTokens = new ArrayList<>();

        final String[] tokenTexts = SecConst.TOKENTEXTS;
        final int[] tokenIds = SecConst.TOKENIDS;

        String[] availableTokens = eeProfile.getValue(EndEntityProfile.AVAILKEYSTORE, 0).split(EndEntityProfile.SPLITCHAR);

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

    public boolean isRenderOtherCertDataSection() {
        return (eeProfile.isCustomSerialNumberUsed() || eeProfile.isValidityStartTimeUsed() || eeProfile.isValidityEndTimeUsed()
                || eeProfile.isCardNumberUsed() || eeProfile.isNameConstraintsPermittedUsed() || eeProfile.isNameConstraintsExcludedUsed()
                || eeProfile.isPsd2QcStatementUsed() || eeProfile.isCabfOrganizationIdentifierUsed());
    }

    public boolean isCustomSerialNumberUsed() {
        return eeProfile.isCustomSerialNumberUsed();
    }

    public boolean isValidityStartTimeUsed() {
        return eeProfile.isValidityStartTimeUsed();
    }

    public String getCustomSerialNumber() {
        final ExtendedInformation ei = userData.getExtendedInformation();
        final BigInteger oldNr = ei != null ? ei.certificateSerialNumber() : null;
        return oldNr != null ? oldNr.toString(16) : "";
    }

    public void setCustomSerialNumber(String customSerialNumber) {
        this.customSerialNumber = customSerialNumber;
    }

    public String getValidityStartTime() {
        ExtendedInformation ei = userData.getExtendedInformation();
        String startTime = null;
        if (ei != null) {
            startTime = ei.getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
            if (startTime == null) {
                startTime = "";
            }
            if (!startTime.trim().equals("")) {
                startTime = ejbcaWebBean.getISO8601FromImpliedUTCOrRelative(startTime);
            }
        }

        return startTime;
    }

    public void setValidityStartTime(final String validityStartTime) {
        this.validityStartTime = validityStartTime;
    }

    public String getValidityTimeTitle() {
        return getEjbcaWebBean().getText("FORMAT_ISO8601") + " " + getEjbcaWebBean().getText("OR") + "("
                + getEjbcaWebBean().getText("DAYS").toLowerCase() + ":" + getEjbcaWebBean().getText("HOURS").toLowerCase() + ":"
                + getEjbcaWebBean().getText("MINUTES").toLowerCase();
    }

    public boolean isValidityStartTimeReadOnly() {
        return !eeProfile.isValidityStartTimeModifiable();
    }

    public boolean isValidityStartTimeRequired() {
        return eeProfile.isRequired(EndEntityProfile.STARTTIME, 0);
    }

    public boolean isValidityEndTimeUsed() {
        return eeProfile.isValidityEndTimeUsed();
    }

    public String getValidityEndTime() {

        ExtendedInformation ei = userData.getExtendedInformation();
        String endTime = null;
        if (ei != null) {
            endTime = ei.getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
        }
        if (endTime == null) {
            endTime = "";
        }
        if (!endTime.trim().equals("")) {
            endTime = ejbcaWebBean.getISO8601FromImpliedUTCOrRelative(endTime);
        }

        return endTime;
    }

    public void setValidityEndTime(final String validityEndTime) {
        this.validityEndTime = validityEndTime;
    }

    public boolean isValidityEndTimeReadOnly() {
        return !eeProfile.isValidityEndTimeModifiable();
    }

    public boolean isValidityEndTimeRequired() {
        return eeProfile.isRequired(EndEntityProfile.ENDTIME, 0);
    }

    public boolean isCardNumberUsed() {
        return eeProfile.isCardNumberUsed();
    }

    public String getCardNumber() {
        return userData.getCardNumber();
    }

    public void setCardNumber(String cardNumber) {
        this.cardNumber = cardNumber;
    }

    public boolean isCardNumberRequired() {
        return eeProfile.isCardNumberRequired();
    }

    public boolean isNameConstraintsPermittedUsed() {
        return eeProfile.isNameConstraintsPermittedUsed();
    }

    public String getNameConstraintsPermittedHelpText() {
        return getEjbcaWebBean().getText("EXT_PKIX_NC_PERMITTED_HELP1") + getEjbcaWebBean().getText("EXT_PKIX_NC_PERMITTED_HELP2")
                + getEjbcaWebBean().getText("EXT_PKIX_NC_PERMITTED_HELP3");
    }

    public boolean isNameConstraintsPermittedRequired() {
        return eeProfile.isNameConstraintsPermittedRequired();
    }

    public boolean isNameConstraintsExcludedUsed() {
        return eeProfile.isNameConstraintsPermittedUsed();
    }

    public String getNameConstraintsExcludedHelpText() {
        return getEjbcaWebBean().getText("EXT_PKIX_NC_EXCLUDED_HELP1") + getEjbcaWebBean().getText("EXT_PKIX_NC_EXCLUDED_HELP2");
    }

    public boolean isNameConstraintsExcludedRequired() {
        return eeProfile.isNameConstraintsPermittedRequired();
    }

    public String getNameConstraintsPermitted() {

        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation(); // create empty one if it doens't exist, to avoid NPEs
        }

        return NameConstraint.formatNameConstraintsList(ei.getNameConstraintsPermitted());
    }

    public void setNameConstraintsPermitted(String nameConstraintsPermitted) {
        this.nameConstraintsPermitted = nameConstraintsPermitted;
    }

    public String getNameConstraintsExcluded() {
        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation(); // create empty one if it doens't exist, to avoid NPEs
        }

        return NameConstraint.formatNameConstraintsList(ei.getNameConstraintsExcluded());

    }

    public void setNameConstraintsExcluded(String nameConstraintsExcluded) {
        this.nameConstraintsExcluded = nameConstraintsExcluded;
    }

    public boolean isUseExtensionData() {
        return eeProfile.getUseExtensiondata();
    }

    public boolean isRenderRawSubjectDN() {
        return userData.getExtendedInformation() != null && userData.getExtendedInformation().getRawSubjectDn() != null;
    }

    public String getRawSubjectDN() {
        return userData.getExtendedInformation().getRawSubjectDn();
    }

    public boolean isPsd2QcStatementUsed() {
        return eeProfile.isPsd2QcStatementUsed();
    }

    
    public String getPsd2NcaName() {

        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation(); // create empty one if it doens't exist, to avoid NPEs
        }

        return ei.getQCEtsiPSD2NCAName() == null ? "" : ei.getQCEtsiPSD2NCAName();
    }

    public void setPsd2NcaName(String psd2NcaName) {
        this.psd2NcaName = psd2NcaName;
    }

    public String getPsd2NcaId() {
        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation(); // create empty one if it doens't exist, to avoid NPEs
        }

        return ei.getQCEtsiPSD2NCAId() == null ? "" : ei.getQCEtsiPSD2NCAId();
    }

    public void setPsd2NcaId(String psd2NcaId) {
        this.psd2NcaId = psd2NcaId;
    }

    public List<String> getPsd2PspRoles() {

        final List<String> psd2pspRoles = new ArrayList<>();

        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation(); // create empty one if it doens't exist, to avoid NPEs
        }

        if (ei.getQCEtsiPSD2RolesOfPSP() != null) {
            for (PSD2RoleOfPSPStatement psd2role : ei.getQCEtsiPSD2RolesOfPSP()) {
                psd2pspRoles.add(psd2role.getName());
            }
        }
        return psd2pspRoles;
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
        return eeProfile.isCabfOrganizationIdentifierUsed();
    }

    public String getCabfOrganizationIdentifier() {
        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation(); // create empty one if it doens't exist, to avoid NPEs
        }

        return ei.getCabfOrganizationIdentifier();
    }

    public void setCabfOrganizationIdentifier(String cabfOrganizationIdentifier) {
        this.cabfOrganizationIdentifier = cabfOrganizationIdentifier;
    }

    public boolean isCabfOrganizationIdentifierReadOnly() {
        return !eeProfile.isCabfOrganizationIdentifierModifiable();
    }

    public boolean isCabfOrganizationIdentifierRequired() {
        return eeProfile.isCabfOrganizationIdentifierRequired();
    }

    public boolean isRenderOtherDataSection() {
        return eeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0) || useKeyRecovery
                || eeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0) || eeProfile.getUse(EndEntityProfile.SENDNOTIFICATION, 0)
                || eeProfile.getUsePrinting();
    }

    public boolean isAllowedRequestsUsed() {
        return eeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0);
    }

    public List<SelectItem> getAllowedRequests() {

        List<SelectItem> allowedRequestsList = new ArrayList<>();

        for (int j = 0; j < 6; j++) {
            allowedRequestsList.add(new SelectItem(j, String.valueOf(j)));
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

    public void setUseKeyRecovery(boolean useKeyRecovery) {
        this.useKeyRecovery = useKeyRecovery;
    }

    public boolean isKeyRecoveryRequired() {
        return eeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE, 0);
    }

    public boolean isUseIssuanceRevocationReason() {
        return eeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
    }

    public boolean isIssuanceRevocationReasonDisabled() {
        return !eeProfile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
    }

    public int getRevocationStatus() {

        int revstatus = RevokedCertInfo.NOT_REVOKED;

        ExtendedInformation revei = userData.getExtendedInformation();
        if (revei != null) {
            String value = revei.getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
            if ((value != null) && ((value).length() > 0)) {
                revstatus = (Integer.parseInt(value));
            }
        }

        return revstatus;
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
        return eeProfile.getUse(EndEntityProfile.SENDNOTIFICATION, 0);
    }

    public boolean isSendNotificationRequired() {
        return eeProfile.isRequired(EndEntityProfile.SENDNOTIFICATION, 0)
                && eeProfile.getValue(EndEntityProfile.SENDNOTIFICATION, 0).equals(EndEntityProfile.TRUE) && userData.getSendNotification();
    }

    public boolean isSendNotification() {
        return userData.getSendNotification();
    }

    public void setSendNotification(boolean sendNotification) {
        this.sendNotification = sendNotification;
    }

    public boolean isUsePrintingEnabled() {
        return eeProfile.getUsePrinting();
    }

    public boolean isPrintingRequired() {
        return userData.getPrintUserData();
    }

    public boolean isUsePrinting() {
        return eeProfile.getPrintingDefault();
    }

    public void setUsePrinting(boolean usePrinting) {
        this.usePrinting = usePrinting;
    }

    public boolean isRenderCSRSection() {
        return userData.getExtendedInformation() != null && (userData.getExtendedInformation().getCertificateRequest() != null
                || userData.getExtendedInformation().getKeyStoreAlgorithmType() != null);
    }

    public boolean isRenderCsr() {
        final byte[] csr = userData.getExtendedInformation().getCertificateRequest();
        return csr != null;
    }

    public String getCsr() {
        String csrPem = StringUtils.EMPTY;
        final byte[] csr = userData.getExtendedInformation().getCertificateRequest();
        if (csr != null) {
            csrPem = new String(CertTools.getPEMFromCertificateRequest(csr));
        }
        return csrPem;
    }

    public boolean isRenderKeyAlgType() {
        return userData.getExtendedInformation().getKeyStoreAlgorithmType() != null;
    }

    public String getKeyAlgType() {
        return userData.getExtendedInformation().getKeyStoreAlgorithmType();

    }

    public String getKeyAlgSubType() {
        return userData.getExtendedInformation().getKeyStoreAlgorithmSubType();
    }

    public void keyRecoveryCheckboxStatusUpdate() {

        boolean keyRecoveryCheckBoxDisabled = false;
        boolean keyRecoveryCheckBoxChecked = false;

        if (getSelectedTokenId() == SecConst.TOKEN_SOFT_BROWSERGEN) {
            keyRecoveryCheckBoxChecked = false;
            keyRecoveryCheckBoxDisabled = true;
        } else {
            if (eeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE, 0)) {
                keyRecoveryCheckBoxDisabled = true;
            } else {
                keyRecoveryCheckBoxDisabled = false;
            }

            if (eeProfile.getValue(EndEntityProfile.KEYRECOVERABLE, 0).equals(EndEntityProfile.TRUE)
                    || eeProfile.isRequired(EndEntityProfile.KEYRECOVERABLE, 0)) {
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

    private boolean doesPasswordAndConfirmationMatch() {
        if (!eeProfile.useAutoGeneratedPasswd() && (eeProfile.isPasswordModifiable())) {
            return eeConfirmPassword.equals(eePassword);
        } else {
            return true;
        }
    }

    private UserView checkAndSetSubjectDN(UserView newUserView) throws EndEntityException {
        StringBuilder subjectDn = new StringBuilder();
        int i = 0;
        for (SubjectDnFieldData subjectDnFieldAndData : getSubjectDnFieldsAndDatas()) {
            String value = null;
            int[] fieldData = eeProfile.getSubjectDNFieldsInOrder(i++);

            
            if (!EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)) {
                value = subjectDnFieldAndData.getFieldValue();
                subjectDnFieldAndData.validateFieldValue(value, fieldData);
            } else {
                if (subjectDnFieldAndData.getIsEmailAndUsesEmailFieldData().getRight()) {
                    value = newUserView.getEmail();
                }
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

            if (subjectDnFieldAndData.getOptions().length >= 1 && StringUtils.isNotBlank(subjectDnFieldAndData.getFieldValue())
                    && !EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)) {
                value = subjectDnFieldAndData.getFieldValueToSave(newUserView, fieldData);
                if (StringUtils.isNotEmpty(value)) {

                    if (subjectDn.length() == 0) {
                        subjectDn.append(value);
                    } else {
                        subjectDn.append(", " + value);
                    }
                }
            }
        }
        newUserView.setSubjectDN(subjectDn.toString());
        return newUserView;
    }

    private UserView checkAndSetSubjectAltName(UserView newUserView) throws EndEntityException {

        StringBuilder subjectAltName = new StringBuilder();
        int i = 0;
        String fieldValue;
        for (final SubjectAltNameFieldData subjectAltNameFieldAndData : getSubjectAltNameFieldDatas()) {
            int[] fieldData = eeProfile.getSubjectAltNameFieldsInOrder(i++);

            if (subjectAltNameFieldAndData.isCopyDataFromCN()) {
                fieldValue = handleCopyFromCN(subjectAltNameFieldAndData, fieldData);
            } else {
                fieldValue = subjectAltNameFieldAndData.getFieldValueToSave(newUserView, fieldData);
            }

            if (StringUtils.isNotBlank(fieldValue)) {
                if (!certProfileSession.getCertificateProfile(selectedCertProfileId).getUseSubjectAlternativeName()) {
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
            resutlFieldValue = handleCopyFromCnUpn(subjectAltNameFieldAndData,
                    eeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]));
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
            int[] sDNfieldData = eeProfile.getSubjectDNFieldsInOrder(i++);
            if (EndEntityProfile.isFieldOfType(sDNfieldData[EndEntityProfile.FIELDTYPE], DnComponents.COMMONNAME)) {
                valueFromCN = dnFieldData.getFieldValue();
                if (StringUtils.isNotBlank(valueFromCN) && StringUtils.isNotBlank(upnFromProfile)) {
                    resutlFieldValue = valueFromCN + "@" + upnFromProfile;
                }
                break;
            }
        }

        if (StringUtils.isBlank(resutlFieldValue) && StringUtils.isNotBlank(upnUserName)) {
            resutlFieldValue = upnUserName + "@" + upnDomain;
        }
        return resutlFieldValue;
    }

    private String handleCopyFromCnDns() {
        String resutlFieldValue = StringUtils.EMPTY;
        int i = 0;
        for (SubjectDnFieldData dnFieldData : getSubjectDnFieldsAndDatas()) {
            int[] sDNfieldData = eeProfile.getSubjectDNFieldsInOrder(i++);

            if (EndEntityProfile.isFieldOfType(sDNfieldData[EndEntityProfile.FIELDTYPE], DnComponents.COMMONNAME)
                    && StringUtils.isNotBlank(dnFieldData.getFieldValue())) {
                resutlFieldValue = dnFieldData.getFieldValue();
                break;
            }
        }
        return resutlFieldValue;
    }

    private UserView checkAndSetSubjectDirName(UserView newUserView) throws EndEntityException {

        StringBuilder subjectDirAttr = new StringBuilder();

        int i = 0;
        for (SubjectDirAttrFieldData subjectDirAttrFieldAndData : getSubjectDirAttrFieldDatas()) {
            int[] fieldData = eeProfile.getSubjectDirAttrFieldsInOrder(i++);
            String fieldValue = subjectDirAttrFieldAndData.getFieldValueToSave(newUserView, fieldData);

            if (StringUtils.isNotBlank(fieldValue)) {
                if (!certProfileSession.getCertificateProfile(selectedCertProfileId).getUseSubjectDirAttributes()) {
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

    /**
     * 
     * @throws IllegalNameException
     * @throws EndEntityException
     * @throws ParseException
     * @throws ParameterException
     * @throws CADoesntExistsException
     * @throws CertificateSerialNumberException
     * @throws EndEntityProfileValidationException
     * @throws CertificateExtensionException
     */
    public void editUser() throws IllegalNameException, EndEntityException, ParseException, ParameterException, CADoesntExistsException,
            CertificateSerialNumberException, EndEntityProfileValidationException, CertificateExtensionException {

        /**************************** First we do all the necessary checks! ************************/
        
        
        if (!eeProfile.useAutoGeneratedPasswd()) {
            if (!isEePasswordProvided()) {
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("REQUIREDPASSWORD"));
                return;
            }
        } else {
            if (statusChangeRequiresPasswordRegen()) {
                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("PASSWORDMUSTBEREGEN"));
                return;
            }
        }
        
        if (!doesPasswordAndConfirmationMatch()) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("PASSWORDSDOESNTMATCH"));
            return;
        }
        
        if(statusChangedIncorrectly()) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("ONLYSTATUSCANBESELECTED"));
            return;
        }
        
        if (selectedCertProfileId == -1) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CERTIFICATEPROFILEMUST"));
            return;
        }

        if (selectedCaId == -1) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CAMUST"));
            return;
        }

        if (selectedTokenId == -1) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("TOKENMUST"));
            return;
        }
        
        if (eeProfile.isNameConstraintsPermittedRequired() && nameConstraintsPermitted.equals(StringUtils.EMPTY)) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("REQUIREDNAMECONSTRAINTPERMITTED"));
            return;
        }

        if (eeProfile.isNameConstraintsExcludedRequired() && nameConstraintsExcluded.equals(StringUtils.EMPTY)) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("REQUIREDNAMECONSTRAINTEXCLUDED"));
            return;
        }
        
        if (eeProfile.getUse(EndEntityProfile.MAXFAILEDLOGINS, 0) && (maxLoginAttemptsStatus.equals("specified"))) {
            try {
                int maxLoginAttemptsProvided = Integer.parseInt(maxLoginAttempts);
                if (maxLoginAttemptsProvided < -1) {
                    addNonTranslatedErrorMessage(getEjbcaWebBean().getText("REQUIREDMAXFAILEDLOGINS"));
                    return;
                }
            } catch (NumberFormatException e) {
                log.debug("Invalid number for max failed log attempts");
                return;
            }
        }
        
        if (eeProfile.getUse(EndEntityProfile.EMAIL, 0) && (eeProfile.isRequired(EndEntityProfile.EMAIL, 0)
                && (emailName.equals(StringUtils.EMPTY) || emailDomain.equals(StringUtils.EMPTY)))) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("REQUIREDEMAIL"));
            return;
        }

        if (eeProfile.isCabfOrganizationIdentifierUsed() && eeProfile.isCabfOrganizationIdentifierRequired()
                && (cabfOrganizationIdentifier.equals(StringUtils.EMPTY))) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("EXT_CABF_ORGANIZATION_IDENTIFIER_REQUIRED"));
            return;
        }
        
        if (eeProfile.getUse(EndEntityProfile.CARDNUMBER, 0) && (!cardNumber.equals(StringUtils.EMPTY)) && (!cardNumber.matches("[0-9]+"))) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("CARDNUMBER_MUSTBE"));
            return;
        }

        if (eeProfile.getUse(EndEntityProfile.SENDNOTIFICATION, 0) && eeProfile.isModifyable(EndEntityProfile.EMAIL, 0)
                && (sendNotification && userData.getEmail().equals(StringUtils.EMPTY))) {
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("NOTIFICATIONADDRESSMUSTBE"));
            return;

        }     
        /**************************** End of the checks! ************************/
        
        userData.setEndEntityProfileId(selectedEeProfileId);

        UserView newUserView = new UserView();
        newUserView.setEndEntityProfileId(selectedEeProfileId);
        newUserView.setUsername(userData.getUsername());

        if (eePassword != null) {
            eePassword = eePassword.trim();
            if (!eePassword.equals("")) {
                newUserView.setPassword(eePassword);
            }
        }

        if (regeneratePassword) {
            newUserView.setPassword("NEWPASSWORD");
        }

        if (selectedPassword != null &&  (!selectedPassword.equals(""))) {
                newUserView.setPassword(selectedPassword);
            
        }

        newUserView.setClearTextPassword(useClearTextPasswordStorage);

        // Start by filling all old ExtendedInformation from the existing user, if any
        // Fields that can be edited are changed below, but we don't want to loose anything else
        //
        // Fields we handle explicitly (view and edit):
        // MAXFAILEDLOGINATTEMPTS
        // EXTENSIONDATA
        // REMAININGLOGINATTEMPTS
        // CUSTOM_REQUESTCOUNTER
        // CUSTOM_REVOCATIONREASON
        // CUSTOM_ENDTIME
        // CERTIFICATESERIALNUMBER
        // NAMECONSTRAINTS_PERMITTED
        // NAMECONSTRAINTS_EXCLUDED
        // 
        // In addition we display information about:
        // RAWSUBJECTDN
        // KEYSTORE_ALGORITHM_TYPE
        // KEYSTORE_ALGORITHM_SUBTYPE
        // CERTIFICATE_REQUEST
        ExtendedInformation ei = userData.getExtendedInformation();
        if (ei == null) {
            ei = new ExtendedInformation();
        }
        
        if(maxLoginAttempts.equals(StringUtils.EMPTY) || maxLoginAttemptsStatus.equals("unlimited")) {
            maxLoginAttempts = "-1";
        }
        
        ei.setMaxLoginAttempts(Integer.parseInt(maxLoginAttempts));
        newUserView.setExtendedInformation(ei);

        if (extensionData != null &&  (eeProfile.getUseExtensiondata())) {
                setExtensionData(extensionData);
            
        }

        if (resetMaxLoginAttempts) {
            ei.setRemainingLoginAttempts(ei.getMaxLoginAttempts());
            newUserView.setExtendedInformation(ei);
        }

        if (emailName == null || emailName.trim().equals("")) {
            if (emailDomain == null || emailDomain.trim().equals("")) {
                newUserView.setEmail("");
            } else {
                // TEXTFIELD_EMAIL empty but not TEXTFIELD_EMAILDOMAIN

                addNonTranslatedErrorMessage(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
                throw new EndEntityException(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
            }
        } else {
            emailName = emailName.trim();
            if (emailDomain != null) {
                emailDomain = emailDomain.trim();
                if (!emailDomain.equals("")) {
                    newUserView.setEmail(emailName + "@" + emailDomain);
                } else {
                    // TEXTFIELD_EMAILDOMAIN empty but not TEXTFIELD_EMAIL
                    addNonTranslatedErrorMessage(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
                    throw new EndEntityException(getEjbcaWebBean().getText("EMAILINCOMPLETE"));
                }
            }
        }

        if (cardNumber != null) {
            newUserView.setCardNumber(cardNumber.trim());
        }

        newUserView = checkAndSetSubjectDN(newUserView);
        newUserView = checkAndSetSubjectAltName(newUserView);
        newUserView = checkAndSetSubjectDirName(newUserView);

        if (eeProfile.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0)) {
            ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(numberOfRequests));
            newUserView.setExtendedInformation(ei);
        }

        newUserView.setKeyRecoverable(keyRecoveryCheckboxStatus.left);
        newUserView.setSendNotification(sendNotification);
        newUserView.setPrintUserData(usePrinting);
        newUserView = checkAndSetMainCertificateData(newUserView);

        // Issuance revocation reason, what state a newly issued certificate will have
        // If it's not modifyable don't even try to modify it
        if (eeProfile.getUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)) {
            String fieldValue = String.valueOf(revocationStatus);

            if (!eeProfile.isModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0)) {
                fieldValue = eeProfile.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
            }
            if (fieldValue != null) {
                ei.setCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON, fieldValue);
                newUserView.setExtendedInformation(ei);
            }
        }
        

        if (validityStartTime != null) {
            validityStartTime = validityStartTime.trim();
            if (validityStartTime.length() > 0) {
                String storeValue = ejbcaWebBean.getImpliedUTCFromISO8601OrRelative(validityStartTime);
                ei.setCustomData(EndEntityProfile.STARTTIME, storeValue);
                newUserView.setExtendedInformation(ei);
            }
        }

        if (validityEndTime != null) {
            validityEndTime = validityEndTime.trim();
            if (validityEndTime.length() > 0) {
                String storeValue = ejbcaWebBean.getImpliedUTCFromISO8601OrRelative(validityEndTime);
                ei.setCustomData(EndEntityProfile.ENDTIME, storeValue);
                newUserView.setExtendedInformation(ei);
            }
        }

        if (customSerialNumber != null && customSerialNumber.length() > 0) {
            ei.setCertificateSerialNumber(new BigInteger(customSerialNumber.trim(), 16));
        } else {
            ei.setCertificateSerialNumber(null);
        }

        if (psd2NcaName != null && psd2NcaName.length() > 0) {
            ei.setQCEtsiPSD2NcaName(psd2NcaName.trim());
        } else {
            ei.setQCEtsiPSD2NcaName(null);
        }

        if (psd2NcaId != null && psd2NcaId.length() > 0) {
            ei.setQCEtsiPSD2NcaId(psd2NcaId.trim());
        } else {
            ei.setQCEtsiPSD2NcaId(null);
        }

        if (psd2PspRoles != null && !psd2PspRoles.isEmpty()) {
            final List<PSD2RoleOfPSPStatement> pspRoles = new ArrayList<>();
            for (String role : psd2PspRoles) {
                pspRoles.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid(role), role));
            }
            ei.setQCEtsiPSD2RolesOfPSP(pspRoles);
        } else {
            ei.setQCEtsiPSD2RolesOfPSP(null);
        }

        if (eeProfile.isCabfOrganizationIdentifierRequired() && StringUtils.isEmpty(cabfOrganizationIdentifier)) {
            throw new ParameterException(ejbcaWebBean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_REQUIRED"));
        } else if (cabfOrganizationIdentifier != null && !cabfOrganizationIdentifier.matches(CabForumOrganizationIdentifier.VALIDATION_REGEX)) {
            throw new ParameterException(ejbcaWebBean.getText("EXT_CABF_ORGANIZATION_IDENTIFIER_BADFORMAT"));
        }
        ei.setCabfOrganizationIdentifier(cabfOrganizationIdentifier);
        newUserView.setExtendedInformation(ei);

        if (nameConstraintsPermitted != null && !nameConstraintsPermitted.trim().isEmpty()) {
            ei.setNameConstraintsPermitted(NameConstraint.parseNameConstraintsList(nameConstraintsPermitted));
        } else {
            ei.setNameConstraintsPermitted(null);
        }

        if (nameConstraintsExcluded != null && !nameConstraintsExcluded.trim().isEmpty()) {
            ei.setNameConstraintsExcluded(NameConstraint.parseNameConstraintsList(nameConstraintsExcluded));
        } else {
            ei.setNameConstraintsExcluded(null);
        }

        newUserView.setExtendedInformation(ei);

        if (eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_GENERATED
                || eeStatus == EndEntityConstants.STATUS_HISTORICAL || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY)
            newUserView.setStatus(eeStatus);

        try {
            // Send changes to database.
            raBean.changeUserData(newUserView, userName);
            addNonTranslatedInfoMessage(ejbcaWebBean.getText("ENDENTITYSAVED"));
        } catch (org.cesecore.authorization.AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("NOTAUTHORIZEDTOEDIT"));
        } catch (org.ejbca.core.ejb.ra.NoSuchEndEntityException e) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("ENDENTITYDOESNTEXIST"));
        } catch (org.cesecore.certificates.ca.IllegalNameException e) {
            if (e.getMessage().equals("Username already taken")) {
                addNonTranslatedErrorMessage(ejbcaWebBean.getText("ENDENTITYALREADYEXISTS"));
            } else {
                throw e;
            }
        } catch (org.ejbca.core.model.approval.ApprovalException e) {
            if (e.getErrorCode().equals(ErrorCode.VALIDATION_FAILED)) {
                addNonTranslatedErrorMessage(ejbcaWebBean.getText("DOMAINBLACKLISTVALIDATOR_VALIDATION_FAILED"));
            } else {
                addNonTranslatedErrorMessage(ejbcaWebBean.getText("THEREALREADYEXISTSAPPROVAL"));
            }
        } catch (org.ejbca.core.model.approval.WaitingForApprovalException e) {
            addNonTranslatedErrorMessage(ejbcaWebBean.getText("REQHAVEBEENADDEDFORAPPR"));
        } catch (org.ejbca.core.EjbcaException e) {
            if (e.getErrorCode().equals(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS)) {
                addNonTranslatedErrorMessage(ejbcaWebBean.getText("SERIALNUMBERALREADYEXISTS"));
            }
            if (e.getErrorCode().equals(ErrorCode.CA_NOT_EXISTS)) {
                addNonTranslatedErrorMessage(ejbcaWebBean.getText("CADOESNTEXIST"));
            }
            if (e.getErrorCode().equals(ErrorCode.FIELD_VALUE_NOT_VALID) || e.getErrorCode().equals(ErrorCode.NAMECONSTRAINT_VIOLATION)) {
                addNonTranslatedErrorMessage(e.getMessage());
            }
        }

    }
    
    public void checkUseInBatch() {
        if (!eeProfile.useAutoGeneratedPasswd() && (useClearTextPasswordStorage)) {
            if (!eeProfile.isPasswordModifiable()) {
                if (selectedPassword.equals(StringUtils.EMPTY)) {
                    addNonTranslatedErrorMessage(ejbcaWebBean.getText("PASSWORDREQUIRED"));
                    useClearTextPasswordStorage = false;
                }
            } else {
                if (eePassword.equals(StringUtils.EMPTY)) {
                    addNonTranslatedErrorMessage(ejbcaWebBean.getText("PASSWORDREQUIRED"));
                    useClearTextPasswordStorage = false;
                }
            }

        }
    }

    private boolean statusChangedIncorrectly() {
        return eeStatus != EndEntityConstants.STATUS_NEW && eeStatus != EndEntityConstants.STATUS_KEYRECOVERY
                && eeStatus != EndEntityConstants.STATUS_GENERATED && eeStatus != EndEntityConstants.STATUS_HISTORICAL;
    }

    private boolean statusChangeRequiresPasswordRegen() {
        return ((eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY) && eeStatus != userData.getStatus()
                && !regeneratePassword && selectedTokenId <= SecConst.TOKEN_SOFT);
    }
    
    private boolean isEePasswordProvided() {
        if (eeProfile.isPasswordModifiable()) {
            if ((eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY) && eeStatus != userData.getStatus()
                    && StringUtils.isBlank(eePassword)) {
                return false;
            }

        } else {
            if ((eeStatus == EndEntityConstants.STATUS_NEW || eeStatus == EndEntityConstants.STATUS_KEYRECOVERY) && eeStatus != userData.getStatus()
                    && Objects.isNull(selectedPassword)) {
                return false;
            }
        }
        return true;
    }

}
