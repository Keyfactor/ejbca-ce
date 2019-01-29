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
package org.ejbca.ui.web.admin.endentityprofiles;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserNotification;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper;
import org.ejbca.util.HttpTools;
import org.ejbca.util.PrinterManager;

/**
 * 
 * JSF MBean backing end entity profile page.
 *
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EndEntityProfileMBean extends BaseManagedBean implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EndEntityProfileMBean.class);

    public static final String PARAMETER_PROFILE_ID = "id";
    private static final int MAX_TEMPLATE_FILESIZE = 2*1024*1024;

    /** Minimum and maximum options to show for password length restriction */
    private static final int PASSWORD_LIMIT_MIN = 4;
    private static final int PASSWORD_LIMIT_MAX = 16;
    private static final int MAX_FAILED_LOGINS_DEFAULT = 3;

    private static final String RELATIVE_TIME_REGEX = "\\d+:\\d?\\d:\\d?\\d"; // example: 90:0:0 or 0:15:30
    private static final String ISO_TIME_REGEX = "\\d{4,}-(0\\d|10|11|12)-[0123]\\d( \\d\\d:\\d\\d(:\\d\\d)?)?([+-]\\d\\d:\\d\\d)?"; // example: 2019-12-31 or 2019-12-31 23:59:59+00:00
    private static final String VALIDITY_TIME_REGEX = "^(" + RELATIVE_TIME_REGEX + "|" + ISO_TIME_REGEX + ")$";
    private static final Pattern validityTimePattern = Pattern.compile(VALIDITY_TIME_REGEX);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;

    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
    private EndEntityProfile profiledata;
    private List<UserNotification> userNotifications; 
    private String[] printerNames = null;
    private Integer profileId;
    private String profileName;
    private boolean viewOnly;
    private final List<String> editerrors = new ArrayList<>();

    private Part templateFileUpload;

    public class NameComponentGuiWrapper implements Serializable {
        private static final long serialVersionUID = 1L;

        private final int[] field;
        private String helpText;
        private final String name;
        private final boolean emailField;
        /** Corresponds to the removal checkboxes on the left */
        private boolean shouldRemove = false;
        /** Stores the last used validation regex in case the user mis-clicks and wants to undo */
        private String lastUsedValidationString = "";

        public NameComponentGuiWrapper(final String name, final int[] field, final boolean emailField) {
            this.name = name;
            this.field = field;
            this.emailField = emailField;
            lastUsedValidationString = getValidationString();
        }

        public boolean isEmailField() {
            return emailField;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return profiledata.getValue(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]);
        }

        public void setValue(final String value) {
            profiledata.setValue(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], StringUtils.trim(value));
        }

        public int[] getField() {
            return field;
        }

        public int getFieldType() {
            return field[EndEntityProfile.FIELDTYPE];
        }

        public int getNumber() {
            return field[EndEntityProfile.NUMBER];
        }

        public String getHelpText() {
            return helpText;
        }

        public void setHelpText(final String helpText) {
            this.helpText = helpText;
        }

        /** Used for "Use End Entity E-mail" only */
        public boolean isUsed() {
            return profiledata.getUse(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]);
        }

        public void setUsed(final boolean use) {
            profiledata.setUse(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], use);
        }

        public boolean getUseEndEntityEmail() {
            return emailField && isUsed();
        }

        public boolean isRequired() {
            return profiledata.isRequired(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]);
        }

        public void setRequired(final boolean required) {
            profiledata.setRequired(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], required);
        }

        public boolean isModifiable() {
            return profiledata.isModifyable(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]);
        }

        public void setModifiable(final boolean modifiable) {
            profiledata.setModifyable(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], modifiable);
        }

        private LinkedHashMap<String, Serializable> validationFromRegex(final String regex) {
            final LinkedHashMap<String, Serializable> validation = new LinkedHashMap<>();
            validation.put(RegexFieldValidator.class.getName(), StringUtils.defaultString(regex));
            return validation;
        }

        public boolean isUseValidation() {
            return null != profiledata.getValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]);
        }

        public void setUseValidation(final boolean use) {
            if (use) {
                if (profiledata.getValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]) == null) {
                    profiledata.setValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], validationFromRegex(lastUsedValidationString));
                }
            } else {
                profiledata.setValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], null);
            }
        }

        public String getValidationString() {
            if (isUseValidation()) {
                return (String) profiledata.getValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]).get(RegexFieldValidator.class.getName());
            } else {
                return "";
            }
        }

        public void setValidationString(final String validationString) {
            lastUsedValidationString = validationString;
            profiledata.setValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], validationFromRegex(lastUsedValidationString));
        }

        public boolean isShouldRemove() {
            return shouldRemove;
        }

        public void setShouldRemove(final boolean shouldRemove) {
            this.shouldRemove = shouldRemove;
        }
    }

    @PostConstruct
    private void postConstruct() {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            ejbcaWebBean.initialize(req, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        if (profiledata == null) {
            final String profileIdParam = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get(PARAMETER_PROFILE_ID);
            if (StringUtils.isEmpty(profileIdParam)) {
                throw new IllegalStateException("Internal error. Missing " + PARAMETER_PROFILE_ID + " HTTP request parameter.");
            }
            profileId = Integer.valueOf(profileIdParam);
            profileName = endEntityProfileSession.getEndEntityProfileName(profileId);
            profiledata = endEntityProfileSession.getEndEntityProfile(profileId);
            userNotifications = new ArrayList<>(profiledata.getUserNotifications());
            viewOnly = !authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES);
        }
    }
    public boolean isViewOnly() {
        return viewOnly;
    }

    public EndEntityProfile getProfiledata() {
        return profiledata;
    }

    public void setProfiledata(final EndEntityProfile profiledata) {
        this.profiledata = profiledata;
    }

    public String getEndEntityProfileName() {
        return profileName;
    }

    public int getEndEntityProfileId() {
        return profileId;
    }

    // PASSWORD, USERNAME AND EMAIL
    public void setUseAutoGeneratedUserName(final boolean autoGeneratedUserName) {
        profiledata.setAutoGeneratedUsername(autoGeneratedUserName);
    }

    public boolean getUseAutoGeneratedUserName() {
        return profiledata.isAutoGeneratedUsername();
    }

    public String getPassword() {
        return profiledata.getPredefinedPassword();
    }

    public void setPassword(final String password) {
        profiledata.setPredefinedPassword(StringUtils.trim(password));
    }

    public boolean getPasswordRequired() {
        return profiledata.isPasswordRequired();
    }

    public void setPasswordRequired(boolean passwordRequired) {
        profiledata.setPasswordRequired(passwordRequired);
    }

    public boolean getAutoGeneratedPassword() {
        return profiledata.useAutoGeneratedPasswd();
    }

    public void setAutoGeneratedPassword(boolean autoGenerate) {
        if (autoGenerate) {
            setPasswordRequired(false);
        }
        profiledata.setAutoGeneratedPassword(autoGenerate);
    }

    public String getCurrentPasswordType() {
        return profiledata.getAutoGeneratedPasswordType();
    }

    public void setCurrentPasswordType(final String passwordType) {
        profiledata.setAutoGeneratedPasswordType(passwordType);
    }

    //
    public List<SelectItem> getPasswordTypes() {
        final List<SelectItem> pwdTypesReturned = new ArrayList<>();
        for (String passwordType : EndEntityProfile.getAvailablePasswordTypes()) {
            final String passwordTypeReadable = ejbcaWebBean.getText(passwordType);
            pwdTypesReturned.add(new SelectItem(passwordType, passwordTypeReadable));
        }
        return pwdTypesReturned;
    }

    public List<SelectItem> getPasswordLengths() {
        final List<SelectItem> pwdLenListReturned = new ArrayList<>();
        for (int len = PASSWORD_LIMIT_MIN; len <= PASSWORD_LIMIT_MAX; len++) {
            pwdLenListReturned.add(new SelectItem(len, String.valueOf(len)));
        }
        return pwdLenListReturned;
    }

    public int getCurrentPasswordLen() {
        return profiledata.getAutoGeneratedPasswordLength();
    }

    public void setCurrentPasswordLen(int len) {
        profiledata.setAutoGeneratedPasswordLength(len);
    }

    public boolean getUseMaxFailLogins() {
        return profiledata.isMaxFailedLoginsUsed();
    }

    public void setUseMaxFailLogins(final boolean use) {
        profiledata.setMaxFailedLoginsUsed(use);
    }

    public boolean getFailedLoginsModifiable() {
        return profiledata.isMaxFailedLoginsModifiable();
    }

    public void setFailedLoginsModifiable(final boolean modifiable) {
        profiledata.setMaxFailedLoginsModifiable(modifiable);
    }

    public Integer getMaxFailedLogins() {
        int maxFail = profiledata.getMaxFailedLogins();
        return maxFail == -1 ? null : maxFail;
    }

    public void setMaxFailedLogins(final Integer maxFail) {
        final int maxFailDbValue = maxFail == null ? -1 : maxFail;
        profiledata.setMaxFailedLogins(maxFailDbValue);
    }

    public boolean getMaxFailLoginsUnlimited() {
        return !profiledata.isMaxFailedLoginsLimited();
    }

    public void setMaxFailLoginsUnlimited(boolean unlimited) {
        if (unlimited) {
            profiledata.setMaxFailedLogins(-1);
        } else {
            int maxFail = profiledata.getMaxFailedLogins();
            profiledata.setMaxFailedLogins(maxFail != -1 ? maxFail : MAX_FAILED_LOGINS_DEFAULT);
        }
    }

    public boolean getBatchGenerationUse() {
        return profiledata.isClearTextPasswordUsed();
    }

    public void setBatchGenerationUse(boolean useBatchGeneration) {
        profiledata.setClearTextPasswordUsed(useBatchGeneration);
        if (!useBatchGeneration) {
            setBatchGenerationDefault(false);
            setBatchGenerationRequired(false);
        }
    }

    public boolean getBatchGenerationDefault() {
        return profiledata.isClearTextPasswordDefault();
    }

    public void setBatchGenerationDefault(boolean batchGenerationDefault) { // Verify, temporary for now
        profiledata.setClearTextPasswordDefault(batchGenerationDefault);
    }

    public boolean getBatchGenerationRequired() {
        return profiledata.isClearTextPasswordRequired();
    }

    public void setBatchGenerationRequired(final boolean required) {
        profiledata.setClearTextPasswordRequired(required);
    }

    //
    public boolean getUseEmail() {
        return profiledata.isEmailUsed();
    }

    //
    public void setUseEmail(boolean useEmail) {
        profiledata.setEmailUsed(useEmail);
    }

    // temporary, verify... 
    public String getEmail() {
        String email = "";
        if (profiledata.getEmailDomain() != null && getUseEmail()) {
            email = profiledata.getEmailDomain();
        }
        return email;
    }

    // as above...
    public void setEmail(final String domain) {
        if (getUseEmail()) {
            profiledata.setEmailDomain(StringUtils.trim(domain));
        }
    }

    //
    public boolean isEmailRequired() {
        return profiledata.isEmailRequired();
    }

    //
    public void setEmailRequired(final boolean emailRequired) {
        profiledata.setEmailRequired(emailRequired);
    }

    //
    public boolean isEmailModifiable() {
        return profiledata.isEmailModifiable();
    }

    //
    public void setEmailModifiable(final boolean emailModifyable) {
        profiledata.setEmailDomainModifiable(emailModifyable);
    }

    // DIRECTIVES

    // SUBJECT DN ATTRIBUTES
    public List<SelectItem> getSubjectDNAttributes() {
        final List<SelectItem> attributesReturned = new ArrayList<>();
        final String[] attributeStrings = EndEntityProfile.getSubjectDNProfileFields();
        for (final String attribute : attributeStrings) {
            if (currentSubjectDnAttribute == null) {
                currentSubjectDnAttribute = attribute;
            }
            final String displayText = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileName(attribute));
            attributesReturned.add(new SelectItem(attribute, displayText));
        }
        return attributesReturned;
    }

    private String currentSubjectDnAttribute;

    public String getCurrentSubjectDNAttribute() {
        return currentSubjectDnAttribute;
    }

    public void setCurrentSubjectDNAttribute(final String attribute) {
        currentSubjectDnAttribute = attribute;
    }

    public void addSubjectDNAttribute() {
        if (StringUtils.isBlank(currentSubjectDnAttribute)) {
            log.debug("No Subject DN attribute type selected");
            return;
        }
        profiledata.addField(currentSubjectDnAttribute);
        subjectDnComponentList = null; // reload state from profile
    }

    public void removeSubjectDnComponent() {
        for (final NameComponentGuiWrapper nameComponent : getSubjectDnComponentList()) {
            if (nameComponent.isShouldRemove()) {
                profiledata.removeField(nameComponent.getFieldType(), nameComponent.getNumber());
            }
        }
        subjectDnComponentList = null; // reload state from profile
    }

    public List<NameComponentGuiWrapper> subjectDnComponentList;

    public List<NameComponentGuiWrapper> getSubjectDnComponentList() {
        if (subjectDnComponentList == null) {
            final List<NameComponentGuiWrapper> components = new ArrayList<>();
            final List<int[]> fieldDataList = new ArrayList<>();
            final int numberOfFields = profiledata.getSubjectDNFieldOrderLength();
            for (int i = 0; i < numberOfFields; i++) {
                fieldDataList.add(profiledata.getSubjectDNFieldsInOrder(i));
            }
            for (int[] field : fieldDataList) {
                final String fieldName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(field[EndEntityProfile.FIELDTYPE]));
                final boolean isEmailField = EndEntityProfile.isFieldOfType(field[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS);
                components.add(new NameComponentGuiWrapper(fieldName, field, isEmailField));
            }
            subjectDnComponentList = components;
        }
        return subjectDnComponentList;
    }

    // OTHER SUBJECT ATTRIBUTES

    public List<NameComponentGuiWrapper> subjectAltNameComponentList;

    public List<SelectItem> getSubjectAltNameTypes() {
        final List<SelectItem> subjectAltNamesReturned = new ArrayList<>();
        final String[] attributeStrings = EndEntityProfile.getSubjectAltnameProfileFields();
        for (final String attribute : attributeStrings) {
            if (EndEntityProfile.isFieldImplemented(attribute)) {
                if (currentSubjectAltName == null) {
                    currentSubjectAltName = attribute;
                }
                final String displayName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileName(attribute));
                subjectAltNamesReturned.add(new SelectItem(attribute, displayName));
            }
        }
        return subjectAltNamesReturned;
    }

    private String currentSubjectAltName;

    public void addSubjectAltName() {
        if (StringUtils.isBlank(currentSubjectAltName)) {
            log.debug("No SAN component type selected.");
            return;
        }
        profiledata.addField(currentSubjectAltName);
        subjectAltNameComponentList = null; // reload state from profile
    }

    public void removeSubjectAltNameComponent() {
        for (final NameComponentGuiWrapper nameComponent : getSubjectAltNameComponentList()) {
            if (nameComponent.isShouldRemove()) {
                profiledata.removeField(nameComponent.getFieldType(), nameComponent.getNumber());
            }
        }
        subjectAltNameComponentList = null; // reload state from profile
    }

    public String getCurrentSubjectAltNameType() {
        return currentSubjectAltName;
    }

    public void setCurrentSubjectAltNameType(final String subjectAltNameType) {
        currentSubjectAltName = subjectAltNameType;
    }

    public List<NameComponentGuiWrapper> getSubjectAltNameComponentList() {
        if (subjectAltNameComponentList == null) {
            final List<NameComponentGuiWrapper> components = new ArrayList<>();
            final List<int[]> fieldDataList = new ArrayList<>();
            final int numberOfFields = profiledata.getSubjectAltNameFieldOrderLength();
            for (int i = 0; i < numberOfFields; i++) {
                fieldDataList.add(profiledata.getSubjectAltNameFieldsInOrder(i));
            }
            for (int[] field : fieldDataList) {
                final String fieldName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(field[EndEntityProfile.FIELDTYPE]));
                final boolean isEmailField = EndEntityProfile.isFieldOfType(field[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME);
                final NameComponentGuiWrapper guiWrapper = new NameComponentGuiWrapper(fieldName, field, isEmailField);
                if (EndEntityProfile.isFieldOfType(field[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
                    guiWrapper.setHelpText(ejbcaWebBean.getText("ALT_MS_UPN_HELP"));
                }
                components.add(guiWrapper);
            }
            subjectAltNameComponentList = components;
        }
        return subjectAltNameComponentList;
    }

    // Subject Directory attributes
    private List<NameComponentGuiWrapper> subjectDirectoryAttributesComponentList;

    public List<SelectItem> getSubjectDirectoryAttributes() {
        final List<SelectItem> subjectDirectoryAttributesReturned = new ArrayList<>();
        final String[] attributeStrings = EndEntityProfile.getSubjectDirAttrProfileFields();
        for (final String attribute : attributeStrings) {
            if (currentSubjectDirectoryAttribute == null) {
                currentSubjectDirectoryAttribute = attribute;
            }
            final String displayName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileName(attribute));
            subjectDirectoryAttributesReturned.add(new SelectItem(attribute, displayName));
        }
        return subjectDirectoryAttributesReturned;
    }

    private String currentSubjectDirectoryAttribute;

    public void addSubjectDirectoryAttribute() {
        profiledata.addField(currentSubjectDirectoryAttribute);
        subjectDirectoryAttributesComponentList = null; // reload state from profile
    }

    public void removeSubjectDirectoryAttributeComponent() {
        for (final NameComponentGuiWrapper nameComponent : getSubjectDirectoryAttributeComponentList()) {
            if (nameComponent.isShouldRemove()) {
                profiledata.removeField(nameComponent.getFieldType(), nameComponent.getNumber());
            }
        }
        subjectDirectoryAttributesComponentList = null; // reload state from profile
    }

    public String getCurrentSubjectDirectoryAttribute() {
        return currentSubjectDirectoryAttribute;
    }

    public void setCurrentSubjectDirectoryAttribute(final String subjectDirectoryAttribute) {
        currentSubjectDirectoryAttribute = subjectDirectoryAttribute;
    }

    public List<NameComponentGuiWrapper> getSubjectDirectoryAttributeComponentList() {
        if (subjectDirectoryAttributesComponentList == null) {
            final List<NameComponentGuiWrapper> components = new ArrayList<>();
            final List<int[]> fieldDataList = new ArrayList<>();
            int numberOfSubjectDirectoryAttributeFields = profiledata.getSubjectDirAttrFieldOrderLength();
            for (int i = 0; i < numberOfSubjectDirectoryAttributeFields; i++) {
                fieldDataList.add(profiledata.getSubjectDirAttrFieldsInOrder(i));
            }
            for (int[] field : fieldDataList) {
                final String fieldName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(field[EndEntityProfile.FIELDTYPE]));
                components.add(new NameComponentGuiWrapper(fieldName, field, false));
            }
            subjectDirectoryAttributesComponentList = components;
        }
        return subjectDirectoryAttributesComponentList;
    }

    // MAIN CERTIFICATE DATA

    public List<SelectItem> getAllCertificateProfiles() {
        final List<SelectItem> allAuthorizedCertProfiles = new ArrayList<>();
        final TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();
        final TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();
        final TreeMap<String, Integer> mergedMap = new TreeMap<>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (final Entry<String,Integer> entry : mergedMap.entrySet()) {
            final int certProfileId = entry.getValue(); // map is inverted
            final String certProfileName = entry.getKey();
            allAuthorizedCertProfiles.add(new SelectItem(certProfileId, certProfileName));
        }
        return allAuthorizedCertProfiles;
    }

    public int getDefaultCertificateProfile() {
        return profiledata.getDefaultCertificateProfile();
    }

    public void setDefaultCertificateProfile(final int certificateProfileId) {
        profiledata.setDefaultCertificateProfile(certificateProfileId);
    }

    public List<Integer> getAvailableCertificateProfiles() {
        return profiledata.getAvailableCertificateProfileIds();
    }

    public void setAvailableCertificateProfiles(final List<Integer> certProfileIds) {
        if (certProfileIds == null) {
            log.debug("setAvailableCertificateProfiles called with null value.");
            return;
        }
        profiledata.setAvailableCertificateProfileIds(certProfileIds);
    }

    public List<SelectItem> getAllCas() {
        final List<SelectItem> list = new ArrayList<>();
        final Map<Integer, String> caidtonamemap = caSession.getCAIdToNameMap();
        final List<Integer> authorizedcas = caSession.getAuthorizedCaIds(getAdmin());
        for (Integer caid : authorizedcas) {
            final String caname = caidtonamemap.get(caid).toString();
            list.add(new SelectItem(caid, caname));
        }
        return list;
    }

    public List<SelectItem> getAllCasWithAnyCaOption() {
        final List<SelectItem> list = new ArrayList<>();
        list.add(new SelectItem(SecConst.ALLCAS, ejbcaWebBean.getText("ANYCA")));
        list.addAll(getAllCas());
        return list;
    }

    public Collection<Integer> getAvailableCas() {
        return profiledata.getAvailableCAs();
    }

    public void setAvailableCas(final Collection<Integer> availableCas) {
        profiledata.setAvailableCAs(availableCas);
    }

    public int getDefaultCa() {
        return profiledata.getDefaultCA();
    }

    public void setDefaultCa(final int defaultCa) {
        profiledata.setDefaultCA(defaultCa);
    }

    public List<SelectItem> getAllHardTokenProfiles() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final HashMap<Integer,String> hardTokens = hardTokenSession.getHardTokenProfileIdToNameMap();
        for (final Map.Entry<Integer,String> entry : hardTokens.entrySet()) {
            final int hardTokenProfileId = entry.getKey();
            final String hardTokenProfileName = entry.getValue();
            selectItems.add(new SelectItem(hardTokenProfileId, hardTokenProfileName));
        }
        return selectItems;
    }

    public List<SelectItem> getAllTokenTypes() {
        final String[] tokenString = SecConst.TOKENTEXTS;
        final int[] tokenIds = SecConst.TOKENIDS;
        final List<SelectItem> selectItems = new ArrayList<>();
        for (int stringElement = 0; stringElement < tokenString.length; stringElement++) {
            final int tokenTypeId = tokenIds[stringElement];
            final String tokenLanguageString = tokenString[stringElement];
            final String displayText = ejbcaWebBean.getText(tokenLanguageString);
            selectItems.add(new SelectItem(tokenTypeId, displayText));
        }
        if (isHardTokenIssuerSystemConfigured()) {
            selectItems.addAll(getAllHardTokenProfiles());
        }
        return selectItems;
    }

    public int getDefaultTokenType() {
        return profiledata.getDefaultTokenType();
    }

    public void setDefaultTokenType(final int defaultTokenType) {
        profiledata.setDefaultTokenType(defaultTokenType);
    }

    public Collection<Integer> getAvailableTokenTypes() {
        return profiledata.getAvailableTokenTypes();
    }

    public void setAvailableTokenTypes(final Collection<Integer> tokenTypes) {
        profiledata.setAvailableTokenTypes(tokenTypes);
    }

    public boolean isHardTokenIssuerSystemConfigured() {
        return ejbcaWebBean.getGlobalConfiguration().getIssueHardwareTokens();
    }

    public boolean isUseHardTokenIssuer() {
        return profiledata.isHardTokenIssuerUsed();
    }

    public void setUseHardTokenIssuer(boolean use) {
        profiledata.setHardTokenIssuerUsed(use);
    }

    public List<SelectItem> getAllHardTokenIssuers() {
        final TreeMap<String, HardTokenIssuerInformation> tokenIssuerMap = hardTokenSession.getHardTokenIssuers(getAdmin());
        final List<SelectItem> hardTokenIssuersReturned = new ArrayList<>();
        for (Entry<String, HardTokenIssuerInformation> hardTokenIssuer : tokenIssuerMap.entrySet()) {
            final int tokenIssuerId = hardTokenIssuer.getValue().getHardTokenIssuerId();
            hardTokenIssuersReturned.add(new SelectItem(tokenIssuerId, hardTokenIssuer.getKey()));
        }
        return hardTokenIssuersReturned;
    }

    public int getDefaultHardTokenIssuer() {
        return profiledata.getDefaultHardTokenIssuer();
    }

    @SuppressWarnings("deprecation")
    public void setDefaultHardTokenIssuer(final int defaultHardTokenIssuerId) {
        profiledata.setDefaultHardTokenIssuer(defaultHardTokenIssuerId);
    }

    public Collection<Integer> getAvailableHardTokenIssuers() {
        return profiledata.getAvailableHardTokenIssuers();
    }

    public void setAvailableHardTokenIssuers(final Collection<Integer> hardTokenIssuers) {
        profiledata.setAvailableHardTokenIssuers(hardTokenIssuers);
    }

    // OTHER CERTIFICATE DATA
    public boolean getUseCertSerialNumber() {
        return profiledata.isCustomSerialNumberUsed();
    }

    public void setUseCertSerialNumber(boolean useCertSerialNr) {
        profiledata.setCustomSerialNumberUsed(useCertSerialNr);
    }

    public String getValidityTimeRegex() {
        return VALIDITY_TIME_REGEX;
    }

    public boolean isUseCertValidityStartTime() {
        return profiledata.isValidityStartTimeUsed();
    }

    public void setUseCertValidityStartTime(boolean useValidityStartTime) {
        profiledata.setValidityStartTimeUsed(useValidityStartTime);
    }

    public String getValidityStartTime() {
        return ejbcaWebBean.getISO8601FromImpliedUTCOrRelative(profiledata.getValidityStartTime());
    }

    public void setValidityStartTime(final String startTime) throws ParseException {
        final String convertedStartTime = ejbcaWebBean.getImpliedUTCFromISO8601OrRelative(StringUtils.trim(startTime));
        profiledata.setValidityStartTime(convertedStartTime);
    }

    public boolean isCertValidityStartTimeModifiable() {
        return profiledata.isValidityStartTimeModifiable();
    }

    public void setCertValidityStartTimeModifiable(boolean startTimeModifyable) {
        profiledata.setValidityStartTimeModifiable(startTimeModifyable);
    }

    public boolean isCertValidityEndTimeModifiable() {
        return profiledata.isValidityEndTimeModifiable();
    }

    public void setCertValidityEndTimeModifiable(boolean endTimeModifyable) {
        profiledata.setValidityEndTimeModifiable(endTimeModifyable);
    }

    public boolean getUseCertValidityEndTime() {
        return profiledata.isValidityEndTimeUsed();
    }

    public void setUseCertValidityEndTime(boolean useValidityEndTime) {
        profiledata.setValidityEndTimeUsed(useValidityEndTime);
    }

    public String getValidityEndTime() {
        return ejbcaWebBean.getISO8601FromImpliedUTCOrRelative(profiledata.getValidityEndTime());
    }

    public void setValidityEndTime(final String endTime) throws ParseException {
        final String convertedEndTime = ejbcaWebBean.getImpliedUTCFromISO8601OrRelative(StringUtils.trim(endTime));
        profiledata.setValidityEndTime(convertedEndTime);
    }

    public String getValidityTimeExample() {
        return ejbcaWebBean.getText("OR").toLowerCase() + " " + ejbcaWebBean.getText("DAYS").toLowerCase() + ":"
                + ejbcaWebBean.getText("HOURS").toLowerCase() + ":" + ejbcaWebBean.getText("MINUTES").toLowerCase();
    }

    public boolean isUseCardNumber() {
        return profiledata.isCardNumberUsed();
    }

    public void setUseCardNumber(boolean useCardNumber) {
        profiledata.setCardNumberUsed(useCardNumber);
    }

    public boolean isCardNumberRequired() {
        return profiledata.isCardNumberRequired();
    }

    public void setCardNumberRequired(boolean cardNumberRequired) {
        profiledata.setCardNumberRequired(cardNumberRequired);
    }

    public boolean isUseNameConstraintsPermitted() {
        return profiledata.isNameConstraintsPermittedUsed();
    }

    public void setUseNameConstraintsPermitted(boolean use) {
        profiledata.setNameConstraintsPermittedUsed(use);
    }

    public boolean isUseNameConstraintsPermittedRequired() {
        return profiledata.isNameConstraintsPermittedRequired();
    }

    public void setUseNameConstraintsPermittedRequired(boolean required) {
        profiledata.setNameConstraintsPermittedRequired(required);
    }

    public boolean getUseNameConstraintsExcluded() {
        return profiledata.isNameConstraintsExcludedUsed();
    }

    public void setUseNameConstraintsExcluded(boolean use) {
        profiledata.setNameConstraintsExcludedUsed(use);
    }

    public boolean getUseNameConstraintsExcludedRequired() {
        return profiledata.isNameConstraintsExcludedRequired();
    }

    public void setUseNameConstraintsExcludedRequired(boolean required) {
        profiledata.setNameConstraintsExcludedRequired(required);
    }

    public boolean isUseCustomCertificateExtensionData() {
        return profiledata.getUseExtensiondata();
    }

    public void setUseCustomCertificateExtensionData(boolean useCustomCertificateExtensionData) {
        profiledata.setUseExtensiondata(useCustomCertificateExtensionData);
    }

    // OTHER DATA

    public boolean getUseNumberOfAllowedRequests() {
        return profiledata.isAllowedRequestsUsed();
    }

    public void setUseNumberOfAllowedRequests(boolean useNumberOfAllowedRequests) {
        profiledata.setAllowedRequestsUsed(useNumberOfAllowedRequests);
    }

    public List<SelectItem> getSelectableNumberOfAllowedRequests() {
        final List<SelectItem> numberOfAllowedRequestsListReturned = new ArrayList<>();
        for (int numberOfRequests = 1; numberOfRequests < 6; numberOfRequests++) {
            final String displayText = String.valueOf(numberOfRequests);
            numberOfAllowedRequestsListReturned.add(new SelectItem(numberOfRequests, displayText));
        }
        return numberOfAllowedRequestsListReturned;
    }

    public int getCurrentNumberOfAllowedRequests() {
        return profiledata.getAllowedRequests();
    }

    public void setCurrentNumberOfAllowedRequests(final int numberOfAllowedRequests) {
        profiledata.setAllowedRequests(numberOfAllowedRequests);
    }

    // Key Recoverable

    public boolean isKeyRecoverableSystemConfigured() {
        return ejbcaWebBean.getGlobalConfiguration().getEnableKeyRecovery();
    }

    public boolean isUseKeyRecoverable() {
        return profiledata.isKeyRecoverableUsed();
    }

    public void setUseKeyRecoverable(boolean useKeyRecoverable) {
        profiledata.setKeyRecoverableUsed(useKeyRecoverable);
    }

    public boolean getKeyRecoverableDefault() {
        return profiledata.isKeyRecoverableDefault();
    }

    public void setKeyRecoverableDefault(boolean keyRecoverableDefault) {
        profiledata.setKeyRecoverableDefault(keyRecoverableDefault);
    }

    public boolean isKeyRecoverableRequired() {
        return profiledata.isKeyRecoverableRequired();
    }

    public void setKeyRecoverableRequired(boolean keyRecoverableReqired) {
        profiledata.setKeyRecoverableRequired(keyRecoverableReqired);
    }

    public boolean getUseRevocationReasonAfterIssuance() {
        return profiledata.isIssuanceRevocationReasonUsed();
    }

    public void setUseRevocationReasonAfterIssuance(final boolean use) {
        profiledata.setIssuanceRevocationReasonUsed(use);
    }

    public RevocationReasons getCurrentRevocationReason() {
        return profiledata.getIssuanceRevocationReason();
    }

    public void setCurrentRevocationReason(final RevocationReasons reason) {
        profiledata.setIssuanceRevocationReason(reason);
    }

    public List<SelectItem> getRevocationReasons() {
        final List<SelectItem> revocationReasonsReturned = new ArrayList<>();
        for (RevocationReasons revocationReason : RevocationReasons.values()) {
            final String humanReadable = revocationReason.getHumanReadable();
            if (revocationReason == RevocationReasons.NOT_REVOKED) {
                revocationReasonsReturned.add(0, new SelectItem(revocationReason, ejbcaWebBean.getText("ACTIVE")));
            } else if (revocationReason == RevocationReasons.CERTIFICATEHOLD) {    
                revocationReasonsReturned.add(1, new SelectItem(revocationReason, ejbcaWebBean.getText("SUSPENDED") + ": " + humanReadable));
            } else {
                revocationReasonsReturned.add(new SelectItem(revocationReason, ejbcaWebBean.getText("REVOKED") + ": " + humanReadable));
            }
        }
        return revocationReasonsReturned;
    }

    public boolean isRevocationReasonModifiable() {
        return profiledata.isIssuanceRevocationReasonModifiable();
    }

    public void setRevocationReasonModifiable(boolean modifiable) {
        profiledata.setIssuanceRevocationReasonModifiable(modifiable);
    }

    public boolean getUseSendNotification() {
        return profiledata.isSendNotificationUsed();
    }

    public void setUseSendNotification(boolean useSendNotification) {
        profiledata.setSendNotificationUsed(useSendNotification);
    }

    public List<UserNotification> getUserNotifications() {
        return userNotifications;
    }

    public void addNotification() {
        log.debug("Adding UserNotification");
        final UserNotification newNotification = new UserNotification();
        newNotification.setNotificationRecipient(UserNotification.RCPT_USER);
        newNotification.setNotificationEventsCollection(new ArrayList<>(Arrays.asList(
                EndEntityConstants.STATUS_NEW, EndEntityConstants.STATUS_INITIALIZED)));
        userNotifications.add(0, newNotification);
    }

    public void removeNotification(final UserNotification notification) {
        log.debug("Removing UserNotification");
        userNotifications.remove(notification);
    }

    public void removeAllNotifications() {
        log.debug("Removing all UserNotifications");
        userNotifications.clear();
    }

    public List<SelectItem> getAllNotificationEvents() {
        final int[] statuses = ViewEndEntityHelper.statusids;
        final String[] statustexts = ViewEndEntityHelper.statustexts;
        final List<SelectItem> allEvents = new ArrayList<>();
        for (int i = 0; i < statuses.length; i++) {
            allEvents.add(new SelectItem(statuses[i], statustexts[i]));
        }
        return allEvents;
    }

    public boolean getSendNotificationDefault() {
        return profiledata.isSendNotificationDefault();
    }

    public void setSendNotificationDefault(boolean isDefault) {
        profiledata.setSendNotificationDefault(isDefault);
    }

    public boolean getSendNotificationRequired() {
        return profiledata.isSendNotificationRequired();
    }

    public void setSendNotificationRequired(boolean isRequired) {
        profiledata.setSendNotificationRequired(isRequired);
    }

    public boolean isUsePrintUserData() {
        return profiledata.getUsePrinting();
    }

    public void setUsePrintUserData(boolean use) {
        profiledata.setUsePrinting(use);
    }

    public boolean isPrintUserDataDefault() {
        return profiledata.getPrintingDefault();
    }

    public void setPrintUserDataDefault(boolean printDefault) {
        profiledata.setPrintingDefault(printDefault);
    }

    public boolean isPrintUserDataRequired() {
        return profiledata.getPrintingRequired();
    }

    public void setPrintUserDataRequired(boolean printRequired) {
        profiledata.setPrintingRequired(printRequired);
    }

    public List<SelectItem> getPrinters() {
        if (printerNames == null) {
            printerNames = PrinterManager.listPrinters();
        }
        final List<SelectItem> printersReturned = new ArrayList<>();
        if (printerNames.length == 0) {
            printersReturned.add(new SelectItem(null, ejbcaWebBean.getText("ERRORNOPRINTERFOUND")));
        } else {
            for (final String printerName : printerNames) {
                printersReturned.add(new SelectItem(printerName, printerName));
            }
        }
        return printersReturned;
    }

    public String getCurrentPrinter() {
        return profiledata.getPrinterName();
    }

    public void setCurrentPrinter(final String printerName) {
        profiledata.setPrinterName(StringUtils.defaultString(printerName));
    }

    public List<SelectItem> getNumberOfCopies() {
        final List<SelectItem> numberOfCopiesReturned = new ArrayList<>();
        for (int copyInt = 0; copyInt < 5; copyInt++) {
            numberOfCopiesReturned.add(new SelectItem(copyInt, String.valueOf(copyInt)));
        }
        return numberOfCopiesReturned;
    }

    public int getCurrentNumberCopies() {
        return profiledata.getPrintedCopies();
    }

    public void setCurrentNumberCopies(int numberOfCopies) {
        profiledata.setPrintedCopies(numberOfCopies);
    }

    public String getCurrentTemplate() {
        final String currentTemplate = profiledata.getPrinterSVGFileName();
        if (StringUtils.isEmpty(currentTemplate)) {
            return ejbcaWebBean.getText("NOTEMPLATEUPLOADED");
        } else {
            return currentTemplate;
        }
    }

    public Part getTemplateFileUpload() {
        return templateFileUpload;
    }

    public void setTemplateFileUpload(final Part templateFileUpload) {
        this.templateFileUpload = templateFileUpload;
    }

    public void uploadTemplate() {
        log.trace(">uploadTemplate");
        if (templateFileUpload == null) {
            log.debug("Template file was null");
            addErrorMessage("YOUMUSTSELECT");
            return;
        }
        byte[] contents = null;
        if (templateFileUpload.getSize() > MAX_TEMPLATE_FILESIZE) {
            addErrorMessage("TEMPLATEUPLOADFAILED");
            return;
        }
        try {
            contents = IOUtils.toByteArray(templateFileUpload.getInputStream(), templateFileUpload.getSize());
        } catch (IOException e) {
            log.info("Caught exception when trying to get template file upload", e);
        }
        final String filename = HttpTools.getUploadFilename(templateFileUpload);
        if (contents == null || contents.length == 0 || StringUtils.isEmpty(filename)) {
            log.info("No template file uploaded, or empty file.");
            addErrorMessage("TEMPLATEUPLOADFAILED");
            return;
        }
        if (log.isDebugEnabled()) {
            log.debug("Uploaded template of " + contents.length + " bytes");
        }
        final String contentsString = new String(contents, StandardCharsets.UTF_8);
        profiledata.setPrinterSVGData(contentsString);
        profiledata.setPrinterSVGFileName(filename);
        log.trace("<uploadTemplate");
    }

    /**
     * Performs validation for fields that cannot be validated using JSF validators or required attributes.
     */
    private void validateProfile() {
        // E-mail
        if (profiledata.isEmailUsed() && !profiledata.isEmailModifiable() && StringUtils.isEmpty(profiledata.getEmailDomain())) {
            editerrors.add(ejbcaWebBean.getText("EMAILEMPTYNONMODIFIABLE"));
        }
        // Subject DN, SAN and Subject Directory Attributes
        validateNameComponents(getSubjectDnComponentList());
        validateNameComponents(getSubjectAltNameComponentList());
        validateNameComponents(getSubjectDirectoryAttributeComponentList());
        // Available Certificate Profiles
        final List<Integer> availableCertProfs = profiledata.getAvailableCertificateProfileIds();
        if (!availableCertProfs.contains(profiledata.getDefaultCertificateProfile())) {
            editerrors.add(ejbcaWebBean.getText("DEFAULTAVAILABLECERTIFICATEPROFILE"));
        }
        // Available CAs
        final List<Integer> availableCas = profiledata.getAvailableCAs();
        if (!availableCas.contains(SecConst.ALLCAS) && !availableCas.contains(profiledata.getDefaultCA())) {
            editerrors.add(ejbcaWebBean.getText("DEFAULTAVAILABLECA"));
        }
        // Token types
        final List<Integer> availableTokenTypes = profiledata.getAvailableTokenTypes();
        if (!availableTokenTypes.contains(profiledata.getDefaultTokenType())) {
            editerrors.add(ejbcaWebBean.getText("DEFAULTAVAILABLETOKENTYPE"));
        }
        // Hard Token Issuers
        if (profiledata.isHardTokenIssuerUsed()) {
            final List<Integer> availableHardTokenIssuers = profiledata.getAvailableHardTokenIssuers();
            if (!availableHardTokenIssuers.contains(profiledata.getDefaultHardTokenIssuer())) {
                editerrors.add(ejbcaWebBean.getText("DEFAULTAVAILABLEHARDTOKENISSUER"));
            }
        }
        // Key Recovery
        if (!ejbcaWebBean.getGlobalConfiguration().getEnableKeyRecovery()) {
            profiledata.setKeyRecoverableUsed(false);
            profiledata.setKeyRecoverableRequired(false);
        }
        // Printing
        if (profiledata.getUsePrinting()) {
            if (StringUtils.isEmpty(profiledata.getPrinterName())) {
                editerrors.add(ejbcaWebBean.getText("MUSTSELECTPRINTER"));
            }
        }
        // Validity time
        if (profiledata.isValidityStartTimeUsed() && !StringUtils.isEmpty(profiledata.getValidityStartTime())) {
            if (!validityTimePattern.matcher(profiledata.getValidityStartTime()).matches()) {
                editerrors.add("Invalid validity start time"); // validated with HTML5 pattern also, but everything should have a server-side check
            }
        }
        if (profiledata.isValidityEndTimeUsed() && !StringUtils.isEmpty(profiledata.getValidityEndTime())) {
            if (!validityTimePattern.matcher(profiledata.getValidityEndTime()).matches()) {
                editerrors.add("Invalid validity end time");
            }
        }
    }
    
    private void validateNameComponents(final List<NameComponentGuiWrapper> list) {
        for (final NameComponentGuiWrapper component : list) {
            final String name = component.getName();
            // empty value + non-modifiable + required = invalid
            // empty value + non-modifiable = could make sense in theory, but most likely a user error, so disallow it as well (consistent with 6.15.x behavior)
            if (StringUtils.isBlank(component.getValue()) && !component.isModifiable()) {
                if (component.isEmailField()) {
                    editerrors.add(ejbcaWebBean.getText("SUBJECTDNEMAILEMPTY"));
                } else {
                    editerrors.add(ejbcaWebBean.getText("SUBJECTDNFIELDEMPTY") + " " + name);
                }
            }
            if (component.isUseValidation()) {
                final String regex = component.getValidationString();
                if (StringUtils.isBlank(regex)) {
                    editerrors.add(ejbcaWebBean.getText("EESUBJDNVALIDATIONEMPTY",  false, name));
                } else {
                    try {
                        Pattern.compile(regex);
                    } catch (PatternSyntaxException e) {
                        editerrors.add(ejbcaWebBean.getText("VALIDATIONREGEXERROR", false, name, e.getMessage()));
                    }
                }
            }
        }
    }

    @Override
    public void clearMessages() {
        super.clearMessages();
        editerrors.clear();
    }

    public void cleanUpUnused() {
        if (profiledata.getAvailableCAs().contains(SecConst.ALLCAS)) {
            profiledata.setAvailableCAs(new ArrayList<>(Arrays.asList(SecConst.ALLCAS)));
        }
        if (!profiledata.isEmailUsed()) {
            profiledata.setEmailRequired(false);
        }
        if (!profiledata.isCardNumberUsed()) {
            profiledata.setCardNumberRequired(false);
        }
        if (!profiledata.isClearTextPasswordUsed()) {
            profiledata.setClearTextPasswordRequired(false);
            profiledata.setClearTextPasswordDefault(false);
        }
        if (!profiledata.isKeyRecoverableUsed()) {
            profiledata.setKeyRecoverableRequired(false);
            profiledata.setKeyRecoverableDefault(false);
        }
        if (!profiledata.isNameConstraintsPermittedUsed()) {
            profiledata.setNameConstraintsPermittedRequired(false);
        }
        if (!profiledata.isNameConstraintsExcludedUsed()) {
            profiledata.setNameConstraintsExcludedRequired(false);
        }
        if (!profiledata.isSendNotificationUsed()) {
            profiledata.setSendNotificationRequired(false);
            profiledata.setSendNotificationDefault(false);
        }
        if (!profiledata.getUsePrinting()) {
            profiledata.setPrintingRequired(false);
            profiledata.setPrintingDefault(false);
        }
    }

    public String saveProfile() throws EndEntityProfileNotFoundException, AuthorizationDeniedException {
        log.trace(">saveProfile");
        clearMessages();
        profiledata.setUserNotifications(userNotifications);
        validateProfile();
        if (editerrors.isEmpty()) {
            cleanUpUnused();
            final String profileName = endEntityProfileSession.getEndEntityProfileName(profileId);
            endEntityProfileSession.changeEndEntityProfile(getAdmin(), profileName, profiledata);
            log.debug("Successfully edited End Entity Profile");
            redirect("editendentityprofiles.xhtml", EndEntityProfilesMBean.PARAMETER_PROFILE_SAVED, true);
            log.trace("<saveProfile: success");
            return "";
        } else {
            for (final String errorMessage : editerrors) {
                addNonTranslatedErrorMessage(errorMessage);
            }
        }
        log.trace("<saveProfile: error");
        return "";
    }

    public void cancel() {
        redirect("editendentityprofiles.xhtml");
    }
}
