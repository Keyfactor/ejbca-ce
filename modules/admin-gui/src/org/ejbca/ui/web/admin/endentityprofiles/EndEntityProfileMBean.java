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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserNotification;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper;
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

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
    private RAInterfaceBean raBean = new RAInterfaceBean();
    private EndEntityProfile profiledata;
    private List<UserNotification> userNotifications; 
    private String[] printerNames = null;
    private Integer profileId;
    private String profileName;
    private boolean viewOnly;
    private final Map<String, String> editerrors = new HashMap<>();

    public class NameComponentGuiWrapper implements Serializable {
        private static final long serialVersionUID = 1L;

        private final int[] field;
        private final String name;
        private final boolean emailField;
        private boolean shouldRemove = false;

        public NameComponentGuiWrapper(final String name, final int[] field, final boolean emailField) {
            this.name = name;
            this.field = field;
            this.emailField = emailField;
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
            if (!EndEntityProfile.isFieldOfType(field[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)) {
                if (StringUtils.isBlank(value) && !isModifiable() && isRequired()) {
                    editerrors.put(name, ejbcaWebBean.getText("SUBJECTDNFIELDEMPTY", true) + ejbcaWebBean.getText(" " + "DN_PKIX_" + name, true));
                } else {
                    profiledata.setValue(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], value);
                }
            } else {
                if (StringUtils.isBlank(value) && !isModifiable() && isRequired()) {
                    editerrors.put(name, ejbcaWebBean.getText("SUBJECTDNEMAILEMPTY", true));
                } else {
                    // Test validation end 
                    profiledata.setValue(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], value);
                }
            }
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

        public boolean isUseValidation() {
            return null != profiledata.getValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]);
        }

        public void setUseValidation(final boolean use) {
            if (use) {
                if (profiledata.getValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER]) == null) {
                    profiledata.setValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], new LinkedHashMap<String, Serializable>());
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
            final LinkedHashMap<String, Serializable> validation = raBean.getValidationFromRegexp(validationString);
            profiledata.setValidation(field[EndEntityProfile.FIELDTYPE], field[EndEntityProfile.NUMBER], validation);
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
            raBean.initialize(req, ejbcaWebBean);
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
        profiledata.setPredefinedPassword(password);
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

    public void setCurrentPasswordType(String passwordType) {
        profiledata.setAutoGeneratedPasswordType(passwordType);
    }

    //
    public List<SelectItem> getPasswordTypes() {
        final List<SelectItem> pwdTypesReturned = new ArrayList<>();
        String passwordTypeReadable;
        for (String passwordType : EndEntityProfile.getAvailablePasswordTypes()) {
            passwordTypeReadable = ejbcaWebBean.getText(passwordType);
            pwdTypesReturned.add(new SelectItem(passwordType, passwordTypeReadable));
        }
        return pwdTypesReturned;
    }

    public List<SelectItem> getPasswordLengths() {
        final List<SelectItem> pwdLenListReturned = new ArrayList<>();
        for (int len = 4; len < 17; len++) {//possible values: 4-16, hard coded here?
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

    public String getMaxFailedLogins() {
        int maxString = profiledata.getMaxFailedLogins();
        if (maxString == -1) {
            return "";
        }
        return String.valueOf(maxString);
    }

    public void setMaxFailedLogins(final String maxFail) {
        final int maxFailDbValue = StringUtils.isBlank(maxFail) ? -1 : Integer.valueOf(maxFail);
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
            profiledata.setMaxFailedLogins(maxFail != -1 ? maxFail : 3);
        }
    }

    public boolean getBatchGenerationUse() {
        return profiledata.isClearTextPasswordUsed();
    }

    public void setBatchGenerationUse(boolean useBatchGeneration) {
        profiledata.setClearTextPasswordUsed(useBatchGeneration);
    }

    //
    public boolean getBatchGenerationDefault() {
//        return profiledata.getValue(EndEntityProfile.CLEARTEXTPASSWORD, 0).equals(EndEntityProfile.TRUE) && getBatchGenerationUse();
        return profiledata.isClearTextPasswordDefault() && getBatchGenerationUse();
    }

    public void setBatchGenerationDefault(boolean batchGenerationDefault) { // Verify, temporary for now
        // FIXME
//        if (batchGenerationDefault) {
//            profiledata.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);
//        }
        if (getBatchGenerationUse()) {
            profiledata.setClearTextPasswordDefault(batchGenerationDefault);
        }
    }

    // FIXME do boolean "require" settings like this make any sense at all? why not just use "modifiable"?
    public boolean getBatchGenerationRequired() {
        return profiledata.isClearTextPasswordRequired() && getBatchGenerationUse();
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
            profiledata.setEmailDomain(domain);
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
        return profiledata.isEmailDomainModifiable();
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
        //for (int stringElement = 0; stringElement < attributeString.length; stringElement++) {
            //final String attribute = attributeString[stringElement];
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
            final List<int[]> fielddatalist = new ArrayList<>();
            final int numberOfFields = profiledata.getSubjectDNFieldOrderLength();
            for (int i = 0; i < numberOfFields; i++) {
                fielddatalist.add(profiledata.getSubjectDNFieldsInOrder(i));
            }
            for (int[] field : fielddatalist) {
                final String fieldName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(field[EndEntityProfile.FIELDTYPE]));
                // FIXME use field[EndEntityProfile.FIELDTYPE] instead
    //            final int fieldType = getFieldType();
    //            final String fieldName = DnComponents.get
    //            return fieldType == EndEntityProfile.EMAIL || fieldType == EndEntityProfile.
                final boolean isEmailField = fieldName.contains("E-mail");
                components.add(new NameComponentGuiWrapper(fieldName, field, isEmailField));
            }
            subjectDnComponentList = components;
        }
        return subjectDnComponentList;
    }

    // OTHER SUBJECT ATTRIBUTES

    public List<NameComponentGuiWrapper> subjectAltNameComponentList;

    public List<SelectItem> getSubjectAltNameTypes() {
        // FIXME this does not change. move to PostConstruct
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

    // temp value atm
    public String getCurrentSubjectAltNameType() {
        return currentSubjectAltName;
    }

    // temp value atm
    public void setCurrentSubjectAltNameType(final String subjectAltNameType) {
        currentSubjectAltName = subjectAltNameType;
    }

    //
    public List<NameComponentGuiWrapper> getSubjectAltNameComponentList() {
        if (subjectAltNameComponentList == null) {
            final List<NameComponentGuiWrapper> components = new ArrayList<>();
            final List<int[]> fielddatalist = new ArrayList<>();
            final int numberOfFields = profiledata.getSubjectAltNameFieldOrderLength();
            for (int i = 0; i < numberOfFields; i++) {
                fielddatalist.add(profiledata.getSubjectAltNameFieldsInOrder(i));
            }
            for (int[] field : fielddatalist) {
                final String fieldName = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(field[EndEntityProfile.FIELDTYPE]));
                // FIXME use field[EndEntityProfile.FIELDTYPE] instead
    //          final int fieldType = getFieldType();
    //          final String fieldName = DnComponents.get
    //          return fieldType == EndEntityProfile.EMAIL || fieldType == EndEntityProfile.
                final boolean isEmailField = fieldName.contains("E-mail");
                components.add(new NameComponentGuiWrapper(fieldName, field, isEmailField));
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

    // 
    public String getCurrentSubjectDirectoryAttribute() {
        return currentSubjectDirectoryAttribute;
    }

    // 
    public void setCurrentSubjectDirectoryAttribute(String subjectDirectoryAttribute) {
        currentSubjectDirectoryAttribute = subjectDirectoryAttribute;
    }

    //
    public List<NameComponentGuiWrapper> getSubjectDirectoryAttributeComponentList() {
        if (subjectDirectoryAttributesComponentList == null) {
            List<NameComponentGuiWrapper> components = new ArrayList<>();
            List<int[]> fielddatalist = new ArrayList<>();
            int numberOfSubjectDirectoryAttributeFields = profiledata.getSubjectDirAttrFieldOrderLength();
            for (int i = 0; i < numberOfSubjectDirectoryAttributeFields; i++) {
                fielddatalist.add(profiledata.getSubjectDirAttrFieldsInOrder(i));
            }
            for (int[] field : fielddatalist) {
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
        final List<Integer> authorizedcas = ejbcaWebBean.getAuthorizedCAIds();
        for (Integer caid : authorizedcas) {
            final String caname = caidtonamemap.get(caid).toString();
            list.add(new SelectItem(caid, caname));
        }
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

    // 
    public List<SelectItem> getAllTokenTypes() {
        String[] tokenString = RAInterfaceBean.tokentexts;
        int[] tokenIds = RAInterfaceBean.tokenids;
        final List<SelectItem> selectItems = new ArrayList<>();
        for (int stringElement = 0; stringElement < tokenString.length; stringElement++) {
            final int tokenTypeId = tokenIds[stringElement];
            final String tokenLanguageString = tokenString[stringElement];
            final String displayText = ejbcaWebBean.getText(tokenLanguageString);
            selectItems.add(new SelectItem(tokenTypeId, displayText));
        }
        if (isHardTokenIssuerSystemConfigured()) {
            selectItems.addAll(getAllHardTokenIssuers());
        }
        return selectItems;
    }

    // verify... 
    public int getDefaultTokenType() {
        return profiledata.getDefaultTokenType();
    }

    //... 
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
        final TreeMap<String, HardTokenIssuerInformation> tokenIssuerMap = ejbcaWebBean.getHardTokenIssuers();
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

    public boolean isUseCertValidityStartTime() {
        return profiledata.isValidityStartTimeUsed();
    }

    public void setUseCertValidityStartTime(boolean useValidityStartTime) {
        profiledata.setValidityStartTimeUsed(useValidityStartTime);
    }

    public String getValidityStartTime() {
        return profiledata.getValidityStartTime();
    }

    public void setValidityStartTime(final String startTime) {
        profiledata.setValidityStartTime(startTime);
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
        return profiledata.getValidityEndTime();
    }

    public void setValidityEndTime(final String endTime) {
        profiledata.setValidityEndTime(endTime);
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
        return profiledata.isAllowedRequestsLimited();
    }

    public void setUseNumberOfAllowedRequests(boolean useNumberOfAllowedRequests) {
        profiledata.setAllowedRequestsLimited(useNumberOfAllowedRequests);
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

    public void setCurrentRevocationReason(RevocationReasons reason) {
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
        userNotifications.add(newNotification);
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
            allEvents.add(new SelectItem(new Integer(statuses[i]).toString(), statustexts[i]));
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

    //
    public boolean isUsePrintUserData() {
        return profiledata.getUsePrinting();
    }

    //
    public void setUsePrintUserData(boolean use) {
        profiledata.setUsePrinting(use);
    }

    //
    public boolean isPrintUserDataDefault() {
        return profiledata.getPrintingDefault();
    }

    //
    public void setPrintUserDataDefault(boolean printDefault) {
        profiledata.setPrintingDefault(printDefault);
    }

    //
    public boolean isPrintUserDataRequired() {
        return profiledata.getPrintingRequired();
    }

    //
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

    public void setCurrentPrinter(String printerName) {
        if (printerName != null) {
            profiledata.setPrinterName(printerName);
        }
    }

    //
    public List<SelectItem> getNumberOfCopies() {
        final List<SelectItem> numberOfCopiesReturned = new ArrayList<>();
        Integer copyInt;
        for (copyInt = 0; copyInt < 5; copyInt++) {
            numberOfCopiesReturned.add(new SelectItem(copyInt.toString(), copyInt.toString()));
        }
        return numberOfCopiesReturned;
    }

    //...
    public String getCurrentNumberCopies() {
        Integer numberOfCopies = profiledata.getPrintedCopies();
        return numberOfCopies.toString();

    }

    // verify
    public void setCurrentNumberCopies(String numberOfCopies) {
        Integer copies = new Integer(numberOfCopies);
        profiledata.setPrintedCopies(copies);
    }

    // verify...
    public String getCurrentTemplate() {
        String currentTemplate = profiledata.getPrinterSVGFileName();
        ;
        if (currentTemplate.equals("")) {
            return ejbcaWebBean.getText("NOTEMPLATEUPLOADED");
        } else {
            return currentTemplate;
        }
    }

    private Part templateFileUpload;

    public Part getTemplateFileUpload() {
        return templateFileUpload;
    }

    public void setTemplateFileUpload(final Part templateFileUpload) {
log.debug("Template file upload: " + templateFileUpload); // XXX removeme
        this.templateFileUpload = templateFileUpload;
    }

    public void uploadTemplate() {
        log.trace(">uploadTemplate");
        if (templateFileUpload == null) {
            log.debug("Template file was null");
            addErrorMessage("YOUMUSTSELECT");
            return;
        }
        final String filename = FilenameUtils.getName(StringUtils.defaultString(templateFileUpload.getName()));
        byte[] contents = null;
        if (templateFileUpload.getSize() > MAX_TEMPLATE_FILESIZE) {
            addErrorMessage("TEMPLATEUPLOADFAILED");
            return;
        }
        try {
            contents = IOUtils.readFully(templateFileUpload.getInputStream(), MAX_TEMPLATE_FILESIZE);
        } catch (IOException e) {
            log.info("Caught exception when trying to get template file upload", e);
        }
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

    public String saveProfile() throws EndEntityProfileNotFoundException, AuthorizationDeniedException {
        log.trace(">saveProfile");
        if (editerrors.isEmpty()) {
            final String profileName = endEntityProfileSession.getEndEntityProfileName(profileId);
            profiledata.setUserNotifications(userNotifications);
            endEntityProfileSession.changeEndEntityProfile(getAdmin(), profileName, profiledata);
            log.debug("Successfully edited End Entity Profile");
            redirect("editendentityprofiles.xhtml", EndEntityProfilesMBean.PARAMETER_PROFILE_SAVED, true);
            log.trace("<saveProfile: success");
            return "";
        } else {
            for (final String errorMessage : editerrors.values()) {
                addNonTranslatedErrorMessage(errorMessage); // FIXME Non translated is temporary for testing
            }
        }
        log.trace("<saveProfile: error");
        return "";
    }

    public void cancel() {
        redirect("editendentityprofiles.xhtml");
    }
}
