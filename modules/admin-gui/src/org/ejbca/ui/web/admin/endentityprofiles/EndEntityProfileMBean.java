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
import javax.faces.bean.ManagedProperty;
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

    private static final int MAX_TEMPLATE_FILESIZE = 2*1024*1024;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    @ManagedProperty(value="#{endEntityProfilesMBean}")
    private EndEntityProfilesMBean endEntityProfilesMBean;

    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
    private RAInterfaceBean raBean = new RAInterfaceBean();
    private EndEntityProfile profiledata;
    // modifications to the return value of profiledata.getUserNotifications does not propagate, so this needs its own variable
    private List<UserNotification> userNotifications; 
    private String[] printerNames = null;
    private int profileId;
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

    //POST CONSTRUCT
    @PostConstruct
    private void postConstruct() {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            ejbcaWebBean.initialize(req, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
//            caBean.initialize(ejbcaWebBean);
            raBean.initialize(req, ejbcaWebBean);
//            tokenBean.initialize(req, ejbcaWebBean);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        profileId = endEntityProfilesMBean.getSelectedEndEntityProfileId().intValue();
        if (profiledata == null) {
            profiledata = endEntityProfileSession.getEndEntityProfile(profileId);
            userNotifications = profiledata.getUserNotifications();
        }
    }

    public boolean isAuthorizedToEdit() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES);
    }

    public boolean isAuthorizedToView() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
    }

    public EndEntityProfilesMBean getEndEntityProfilesMBean() {
        return endEntityProfilesMBean;
    }

    //     
    public void setEndEntityProfilesMBean(EndEntityProfilesMBean endEntityProfilesMBean) {
        this.endEntityProfilesMBean = endEntityProfilesMBean;
    }

    // remove this?
    public boolean isViewOnly() {
        return endEntityProfilesMBean.isViewOnly();
    }

    public EndEntityProfile getProfiledata() {
        return profiledata;
    }

    public void setProfiledata(final EndEntityProfile profiledata) {
        this.profiledata = profiledata;
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

    //  
    /*public String getCurrentDefaultCertProfile() {
        int certProfile = profiledata.getDefaultCertificateProfile();
        String retValue = "";
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> mergedMap = new TreeMap<>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (String defaultCertProfile : mergedMap.keySet()) {
            int certprofid = mergedMap.get(defaultCertProfile).intValue();
            if (certprofid == certProfile) {
                retValue = defaultCertProfile;
            }
        }
        return retValue;
    }

    // some value...
    public void setCurrentDefaultCertProfile(String defaultCertProfile) {
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> mergedMap = new TreeMap<>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        int certprofid = mergedMap.get(defaultCertProfile).intValue();
        profiledata.setDefaultCertificateProfile(certprofid);
    }

    // new method...
    public void setCurrentAvailableCertProfiles(Collection<String> profiles) {
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> mergedMap = new TreeMap<>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        Collection<Integer> idCollection = new ArrayList<>();
        for (String profile : profiles) {
            int certprofid = mergedMap.get(profile).intValue();
            idCollection.add(certprofid);
        }
        profiledata.setAvailableCertificateProfileIds(idCollection);
    }

    // getter for above new method
    public Collection<String> getCurrentAvailableCertProfiles() {
        Collection<Integer> availableCertProfiles = profiledata.getAvailableCertificateProfileIds();
        Collection<String> profilesReturned = new ArrayList<>();
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();
        TreeMap<String, Integer> mergedMap = new TreeMap<>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (String profile : mergedMap.keySet()) {
            for (int id : availableCertProfiles) {
                if (id == mergedMap.get(profile).intValue()) {
                    profilesReturned.add(profile);
                }
            }
        }
        return profilesReturned;
    }*/
    
   /* public Collection<String> getAllAvailableCertificateProfiles() {
        
        Collection<Integer> availableCertProfiles = profiledata.getAvailableCertificateProfileIds();
        Collection<String> profilesReturned = new ArrayList<>();
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();
        TreeMap<String, Integer> mergedMap = new TreeMap<>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (String profile : mergedMap.keySet()) {
            for (int id : availableCertProfiles) {
                if (id == mergedMap.get(profile).intValue()) {
                    profilesReturned.add(profile);
                }
            }
        }
        return profilesReturned;
    } */

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
//        Collection<Integer> tokensAsIntegers = new ArrayList<>();
//        Collection<String> tokensAsStrings = new ArrayList<>();
//        tokensAsIntegers = profiledata.getAvailableTokenTypes();
//        for (int tokenIntValue : tokensAsIntegers) {
//            Integer tokenIntObject = new Integer(tokenIntValue);
//            tokensAsStrings.add(tokenIntObject.toString());
//        }
//        return tokensAsStrings;
        return profiledata.getAvailableTokenTypes();
    }

    public void setAvailableTokenTypes(final Collection<Integer> tokenTypes) {
//        String[] values = tokensAsStrings.toArray(new String[0]);
//        String availableTokens = raBean.getAvailableTokenTypes(getCurrentDefaultToken(), values);
//        profiledata.setValue(EndEntityProfile.AVAILKEYSTORE, 0, availableTokens);
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

    /*
    // verify this
    public boolean isCurrentRevocationReason(SelectItem currentRevocationReasonItem) {
        final String value = getCurrentRevocationReason();
        final String reason = currentRevocationReasonItem.getLabel();
        return reason.equals(value);
    }*/

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

    public void setUserNotifications(final List<UserNotification> userNotifications) {
        this.userNotifications = userNotifications;
    }

    public void addNotification() {
        log.debug("Adding UserNotification");
        UserNotification newNotification = new UserNotification();
        //profiledata.addUserNotification(newNotification);
        userNotifications.add(newNotification);
    }

    public void removeNotification(final UserNotification notification) {
        log.debug("Removing UserNotification");
//        profiledata.removeUserNotification(notification);
        userNotifications.remove(notification);
    }

    public void removeAllNotifications() {
        log.debug("Removing all UserNotifications");
        userNotifications.clear();
//        for (final UserNotification notification : new ArrayList<>(profiledata.getUserNotifications())) {
//            profiledata.removeUserNotification(notification);
//        }
    }

    // experimental
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
            String profileName = endEntityProfileSession.getEndEntityProfileName(profileId);
            profiledata.setUserNotifications(userNotifications);
            endEntityProfileSession.changeEndEntityProfile(getAdmin(), profileName, profiledata);
            log.trace("<saveProfile: success");
            return "profilesaved";
        } else {
            for (final String errorMessage : editerrors.values()) {
                addNonTranslatedErrorMessage(errorMessage); // FIXME Non translated is temporary for testing
            }
        }
        log.trace("<saveProfile: error");
        return "";
        // do check if no errors
    }

    public String cancel() {
        return "cancel";
    }

    public void doNothing() {
        // Dummy method to force a client-server roundtrip
    }

    //==========================================================================================================================================================================   
/*
    // Temporary methods, remove when it is possible
    public boolean getCheckBoxValue() {
        return false;
    }

    public void setCheckBoxValue(boolean bool) {//REMOVE?? 

    }*/

    // UPLOAD TEMPLATE:
    /*if(request.getParameter(BUTTON_UPLOADTEMPLATE) != null){
       includefile="uploadtemplate.jspf";
     }*/

    /*
    <% 
    int row = 0;
    %>
    <body > 
    <script type="text/javascript">
    <!--  
    
    function check()
    {  
    
    if(document.uploadfile.<%= FILE_TEMPLATE %>.value == ''){   
      alert("<%= ejbcawebbean.getText("YOUMUSTSELECT", true) %>"); 
    }else{  
      return true;  
    }
    
    return false;
    }
    -->
    </script>
    
      <c:set var="csrf_tokenname"><csrf:tokenname/></c:set>
      <c:set var="csrf_tokenvalue"><csrf:tokenvalue/></c:set>
    
    <div align="center">
    <h2><%= ejbcawebbean.getText("UPLOADUSERDATATEMP") %></h2>
    <h3><%= ejbcawebbean.getText("ENDENTITYPROFILE")+ " : "%> <c:out value="<%= profile %>"/></h3>
    </div>
    
    <form name="uploadfile" action="<%= THIS_FILENAME %>?${csrf_tokenname}=${csrf_tokenvalue}" method="post" enctype='multipart/form-data' >
    <table class="action" width="100%" border="0" cellspacing="3" cellpadding="3">
     <tr id="Row<%=row++%2%>"> 
       <td width="49%" valign="top"> 
         &nbsp;
       </td>
       <td width="51%" valign="top" align="right"> 
         <a href="<%=THIS_FILENAME %>"><%= ejbcawebbean.getText("BACKTOENDENTITYPROFILES") %></a>
       </td>
     </tr>
     <tr  id="Row<%=row++%2%>"> 
       <td width="49%" valign="top" align="right"><%= ejbcawebbean.getText("PATHTOTEMPLATE") %></td>
       <td width="51%" valign="top">     
         <input type="hidden" name='<%= ACTION %>' value='<%= ACTION_UPLOADTEMP %>'>            
         <input TYPE="FILE" NAME="<%= FILE_TEMPLATE %>" size="40">            
       </td>
     </tr>
     <tr  id="Row<%=row++%2%>"> 
       <td width="49%" valign="top" align="right"> 
         &nbsp;
       </td>
       <td width="51%" valign="top">     
         <input type="submit" name="<%= BUTTON_UPLOADFILE %>" onClick='return check()' value="<%= ejbcawebbean.getText("UPLOADTEMPLATE") %>" >
         &nbsp;&nbsp;&nbsp;
         <input type="submit" name="<%= BUTTON_CANCEL %>" value="<%= ejbcawebbean.getText("CANCEL") %>">     
       </td>
     </tr>
    </table>
    </form>
    */
    //¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

    // END

    // RANDOM STUFF ..REMOVE??

    //??
    // public String currentProfileId = null;

    //

    //??
    //public void setSelectedEndEntityProfileId(String id) {
    //  currentProfileId = id;
    //}

    //??
    /*public void handleFields() {
       // per field below...
    }*/

    //??

    //RANDOM CODE FROM OLD JSP... COMPARE WITH THIS CODE TO FIND WHAT MIGHT BE MISSING

    //If we do use password (boolean is true), we should not use auto-generated

    /*public boolean isUsePassword() {
       return profiledata.getUse(EndEntityProfile.PASSWORD,0);
    }*/

    /*
    public void checkAutoGenBox(){
       String usebox = CHECKBOX_USE_PASSWORD;
       String valuefield = TEXTFIELD_PASSWORD;
       String reqbox = CHECKBOX_REQUIRED_PASSWORD;
       String modifyablebox = CHECKBOX_MODIFYABLE_PASSWORD;
       String pwdtypeselect = SELECT_AUTOPASSWORDTYPE;
       String pwdlenselect = SELECT_AUTOPASSWORDLENGTH;
    
       if(usebox.checked){
         valuefield.value = "";
         valuefield.disabled = true;
         pwdtypeselect.disabled = false;
         pwdlenselect.disabled = false;
         reqbox.checked = false;
         reqbox.disabled = true;
         modifyablebox.checked = false;
         modifyablebox.disabled = true;
       }
       else{    
         valuefield.disabled = false;
         pwdtypeselect.disabled = true;
         pwdlenselect.disabled = true;
         reqbox.disabled = false;
         modifyablebox.disabled = false;
       }
     }
    */

    /*
    <select name="<%=SELECT_PRINTINGCOPIES %>" size="1"  <% if(!used || !authorizedToEdit) out.write(" disabled "); %>>
    <%    for(int i=0; i < 5;i++){ %>
    <option <%  if(i == profiledata.getPrintedCopies()){
                   out.write(" selected "); 
              }
             %>
           value='<c:out value="<%= i %>"/>'>
           <c:out value="<%= i %>"/></option>
    <%   }%>
    </select>
    
    */

    //static final String CHECKBOX_VALUE  = EndEntityProfile.TRUE;

    /*
     public String getCurrentPasswordLen() {
       String str;
       str = getCurrentPasswordLenInt().toString();
       return str;
     }
     
     
     public Integer getCurrentPasswordLenInt() {
       return profiledata.getAutoGenPwdStrength() ;
     }
     
     public void setCurrentPasswordLenInt(int minPwdLen) {
       profiledata.setMinPwdStrength(minPwdLen);
     }
     
     */

    /*public void setUseAutoGeneratedUserNameTrue() {
       profiledata.useAutoGeneratedPasswd();
    }*/

    /*
    //Imported/copied from jsp file, edit ee section:
    if( action.equals(ACTION_EDIT_PROFILE)){
        // Display edit access rules page.
      profile = request.getParameter(HIDDEN_PROFILENAME); 
      if(profile != null){
        if(!profile.trim().equals("")){
            profiledata = raBean.getTemporaryEndEntityProfile(); 
            if(profiledata == null){
              profiledata = raBean.getEndEntityProfile(profile); 
            }
            // Save changes.
            profiledata.setAllowMergeDnWebServices(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_ALLOW_MERGEDN_WEBSERVICES)));
            // i might wanna import all static strings from jsp to be able to use above... 
            profiledata.setRequired(EndEntityProfile.USERNAME, 0 , true);
            profiledata.setModifyable(EndEntityProfile.USERNAME, 0 , !ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_AUTOGENERATED_USERNAME)));
    
            profiledata.setValue(EndEntityProfile.PASSWORD, 0  ,request.getParameter(TEXTFIELD_PASSWORD));
            profiledata.setUse(EndEntityProfile.PASSWORD, 0  , !ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_PASSWORD)));
            profiledata.setRequired(EndEntityProfile.PASSWORD, 0  ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_PASSWORD)));
            profiledata.setModifyable(EndEntityProfile.PASSWORD, 0 , true);
    
            profiledata.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0  ,request.getParameter(CHECKBOX_CLEARTEXTPASSWORD));
            profiledata.setRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_CLEARTEXTPASSWORD))); 
            profiledata.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_CLEARTEXTPASSWORD))); 
            
            profiledata.setValue(EndEntityProfile.AUTOGENPASSWORDTYPE, 0, request.getParameter(SELECT_AUTOPASSWORDTYPE));
            profiledata.setValue(EndEntityProfile.AUTOGENPASSWORDLENGTH, 0, request.getParameter(SELECT_AUTOPASSWORDLENGTH));
            
            try {
                profiledata.setMinPwdStrength(Integer.parseInt(request.getParameter(TEXTFIELD_MINPWDSTRENGTH)));
            } catch(NumberFormatException ignored) {}
    
            int nValue = -1;
            try {
                nValue = Integer.parseInt(request.getParameter(TEXTFIELD_MAXFAILEDLOGINS));
            } catch(NumberFormatException ignored) {}
            value = request.getParameter(RADIO_MAXFAILEDLOGINS);
            if(RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED.equals(value) || nValue < -1) {
               value = "-1";
            } else {
               value = Integer.toString(nValue);
            }
            profiledata.setValue(EndEntityProfile.MAXFAILEDLOGINS, 0, value);
            profiledata.setRequired(EndEntityProfile.MAXFAILEDLOGINS, 0, raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_MAXFAILEDLOGINS)));
            profiledata.setUse(EndEntityProfile.MAXFAILEDLOGINS, 0, raBean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_MAXFAILEDLOGINS)));
            profiledata.setModifyable(EndEntityProfile.MAXFAILEDLOGINS, 0, raBean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_MAXFAILEDLOGINS)));
            
            profiledata.setReverseFieldChecks(raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REVERSEFIELDCHECKS)));
            
            numberofsubjectdnfields = profiledata.getSubjectDNFieldOrderLength();
            for (int i=0; i < numberofsubjectdnfields; i ++) {
               fielddata = profiledata.getSubjectDNFieldsInOrder(i);
               final String subjectDnTextfield = request.getParameter(TEXTFIELD_SUBJECTDN + i);
               final int dnId = DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]);
               final String fieldName = DnComponents.dnIdToProfileName(dnId);
               if (!EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS) ) {
                   if ((subjectDnTextfield == null) || (subjectDnTextfield.trim().equals("")) && 
                           raBean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTDN + i)) == false && 
                                   raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDN + i)) == true) {
                       editerrors.put(TEXTFIELD_SUBJECTDIRATTR + i, ejbcawebbean.getText("SUBJECTDNFIELDEMPTY", true) 
                               + ejbcawebbean.getText("DN_PKIX_".concat(fieldName), true));
                   } else {
                       profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                               raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDN + i)));
                       profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , subjectDnTextfield);                
                       profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                               raBean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTDN + i)));    
                   }
               } else {
                   if ((request.getParameter(TEXTFIELD_EMAIL) == null) || (request.getParameter(TEXTFIELD_EMAIL) == "")  && 
                           raBean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_EMAIL)) == false && 
                                   raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDN + i)) == true) {
                       editerrors.put(TEXTFIELD_EMAIL, ejbcawebbean.getText("SUBJECTDNEMAILEMPTY", true));
                   } else {
                       profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                               raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDN + i)));
                       profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                               request.getParameter(TEXTFIELD_EMAIL));                
                       profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] ,
                               raBean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_EMAIL)));
                   } 
               }
               
               final boolean useValidation = raBean.getEndEntityParameter(request.getParameter(CHECKBOX_VALIDATION_SUBJECTDN + i));
               if (useValidation) {
                   String validationRegex = request.getParameter(TEXTFIELD_VALIDATION_SUBJECTDN + i);
                   final LinkedHashMap<String,Serializable> validation = ejbcarabean.getValidationFromRegexp(validationRegex);
                   try {
                       EndEntityValidationHelper.checkValidator(fieldName, RegexFieldValidator.class.getName(), validationRegex);
                   } catch (EndEntityFieldValidatorException e) {
                       editerrors.put(TEXTFIELD_VALIDATION_SUBJECTDN + i, e.getMessage());
                   }
                   profiledata.setValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER], validation);
               } else {
                   profiledata.setValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER], null);
               }
            }
    
            numberofsubjectaltnamefields = profiledata.getSubjectAltNameFieldOrderLength();
    
            for(int i=0; i < numberofsubjectaltnamefields; i ++){
               fielddata = profiledata.getSubjectAltNameFieldsInOrder(i);
               if ( EndEntityProfile.isFieldOfType(fielddata[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME) ) {
                   profiledata.setUse( fielddata[EndEntityProfile.FIELDTYPE], fielddata[EndEntityProfile.NUMBER],
                           raBean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_SUBJECTALTNAME + i)) );
               }
               profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , request.getParameter(TEXTFIELD_SUBJECTALTNAME + i));                
               profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                       raBean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTALTNAME + i)));
               profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                       raBean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTALTNAME + i)));
            
               final boolean useValidation = raBean.getEndEntityParameter(request.getParameter(CHECKBOX_VALIDATION_SUBJECTALTNAME + i));
               if (useValidation) {
                   String validationRegex = request.getParameter(TEXTFIELD_VALIDATION_SUBJECTALTNAME + i);
                   final LinkedHashMap<String,Serializable> validation = ejbcarabean.getValidationFromRegexp(validationRegex);
                   try {
                       final int dnId = DnComponents.profileIdToDnId(fielddata[EndEntityProfile.FIELDTYPE]);
                       final String fieldName = DnComponents.dnIdToProfileName(dnId);
                       EndEntityValidationHelper.checkValidator(fieldName, RegexFieldValidator.class.getName(), validationRegex);
                   } catch (EndEntityFieldValidatorException e) {
                       editerrors.put(TEXTFIELD_VALIDATION_SUBJECTALTNAME + i, e.getMessage());
                   }
                   profiledata.setValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER], validation);
               } else {
                   profiledata.setValidation(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER], null);
               }
            } 
           
            numberofsubjectdirattrfields = profiledata.getSubjectDirAttrFieldOrderLength();
    
            for(int i=0; i < numberofsubjectdirattrfields; i ++){
               fielddata = profiledata.getSubjectDirAttrFieldsInOrder(i);
               profiledata.setValue(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , request.getParameter(TEXTFIELD_SUBJECTDIRATTR + i));                
               profiledata.setRequired(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                       ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SUBJECTDIRATTR + i)));
               profiledata.setModifyable(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER] , 
                                       ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_SUBJECTDIRATTR + i)));
            } 
    
            profiledata.setValue(EndEntityProfile.EMAIL, 0,request.getParameter(TEXTFIELD_EMAIL));
            profiledata.setRequired(EndEntityProfile.EMAIL, 0,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_EMAIL)));
            profiledata.setModifyable(EndEntityProfile.EMAIL, 0,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_EMAIL))); 
            profiledata.setUse(EndEntityProfile.EMAIL, 0,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_EMAIL))); 
    
            profiledata.setValue(EndEntityProfile.KEYRECOVERABLE, 0, ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_KEYRECOVERABLE)) ? EndEntityProfile.TRUE : EndEntityProfile.FALSE);
            profiledata.setRequired(EndEntityProfile.KEYRECOVERABLE, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_KEYRECOVERABLE)));
            profiledata.setUse(EndEntityProfile.KEYRECOVERABLE, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_KEYRECOVERABLE)));
            
            profiledata.setReUseKeyRecoveredCertificate(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REUSECERTIFICATE)));
            
              profiledata.setValue(EndEntityProfile.CARDNUMBER, 0, ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_CARDNUMBER)) ? EndEntityProfile.TRUE : EndEntityProfile.FALSE);
              profiledata.setRequired(EndEntityProfile.CARDNUMBER, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_CARDNUMBER)));
              profiledata.setUse(EndEntityProfile.CARDNUMBER, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_CARDNUMBER))); 
    
            
            profiledata.setValue(EndEntityProfile.SENDNOTIFICATION, 0, ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SENDNOTIFICATION)) ? EndEntityProfile.TRUE : EndEntityProfile.FALSE);
            profiledata.setRequired(EndEntityProfile.SENDNOTIFICATION, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_SENDNOTIFICATION)));
            profiledata.setUse(EndEntityProfile.SENDNOTIFICATION, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_SENDNOTIFICATION))); 
    
            String issrevreason =  request.getParameter(SELECT_ISSUANCEREVOCATIONREASON);
            if(issrevreason != null)
                profiledata.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0,issrevreason);
              else
                profiledata.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0,""+RevokedCertInfo.NOT_REVOKED);
            profiledata.setModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_MODIFYABLE_ISSUANCEREVOCATIONREASON)));
            profiledata.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_ISSUANCEREVOCATIONREASON))); 
            profiledata.setRequired(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0,true);
    
            profiledata.setValue(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0, "");
            profiledata.setRequired(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_NC_PERMITTED)));
            profiledata.setUse(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_NC_PERMITTED)));
            
            profiledata.setValue(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0, "");
            profiledata.setRequired(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_REQUIRED_NC_EXCLUDED)));
            profiledata.setUse(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_NC_EXCLUDED)));
    
            profiledata.setUse(EndEntityProfile.CERTSERIALNR, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_CERTSERIALNR)));
    
            profiledata.setUseExtensiondata(CHECKBOX_VALUE.equalsIgnoreCase(request.getParameter(CHECKBOX_USE_EXTENSIONDATA)));
    
            String defaultcertprof =  request.getParameter(SELECT_DEFAULTCERTPROFILE);
            String[] values = request.getParameterValues(SELECT_AVAILABLECERTPROFILES);
            // Only set default cert profile value if it is among the available ones, if javascript check
            // was bypassed, set default to nothing in order to avoid anything bad happening
            if (ArrayUtils.contains(values, defaultcertprof)) {
                profiledata.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, defaultcertprof);
                profiledata.setRequired(EndEntityProfile.DEFAULTCERTPROFILE, 0,true);
            } else {
                profiledata.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "-1");
                profiledata.setRequired(EndEntityProfile.DEFAULTCERTPROFILE, 0,true);
            }
            final String availablecertprofiles = ejbcarabean.getAvailableCertProfiles(defaultcertprof, values);
            profiledata.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, availablecertprofiles);
            profiledata.setRequired(EndEntityProfile.AVAILCERTPROFILES, 0, true);    
    
            String defaultca =  request.getParameter(SELECT_DEFAULTCA);
            profiledata.setValue(EndEntityProfile.DEFAULTCA, 0,defaultca);
            profiledata.setRequired(EndEntityProfile.DEFAULTCA, 0,true);
    
            values = request.getParameterValues(SELECT_AVAILABLECAS);
    
            if (defaultca != null) {
              final String availablecas = ejbcarabean.getAvailableCasString(values, defaultca);
              profiledata.setValue(EndEntityProfile.AVAILCAS, 0,availablecas);
              profiledata.setRequired(EndEntityProfile.AVAILCAS, 0,true);    
            }
    
    
            String defaulttokentype =  request.getParameter(SELECT_DEFAULTTOKENTYPE);
            profiledata.setValue(EndEntityProfile.DEFKEYSTORE, 0,defaulttokentype);
            profiledata.setRequired(EndEntityProfile.DEFKEYSTORE, 0,true);
    
            values = request.getParameterValues(SELECT_AVAILABLETOKENTYPES);
    
            if(defaulttokentype != null){
              final String availabletokentypes = ejbcarabean.getAvailableTokenTypes(defaulttokentype, values);
              profiledata.setValue(EndEntityProfile.AVAILKEYSTORE, 0, availabletokentypes);
              profiledata.setRequired(EndEntityProfile.AVAILKEYSTORE, 0, true);    
            }
    
            profiledata.setUse(EndEntityProfile.AVAILTOKENISSUER, 0 ,ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_HARDTOKENISSUERS))); 
    
            String defaulthardtokenissuer =  request.getParameter(SELECT_DEFAULTHARDTOKENISSUER);
            profiledata.setValue(EndEntityProfile.DEFAULTTOKENISSUER, 0,defaulthardtokenissuer);
            profiledata.setRequired(EndEntityProfile.DEFAULTTOKENISSUER, 0,true);
    
            values = request.getParameterValues(SELECT_AVAILABLEHARDTOKENISSUERS);
    
            if(defaulthardtokenissuer != null){
              final String availablehardtokenissuers = ejbcarabean.getAvailableHardTokenIssuers(defaulthardtokenissuer, values);
              profiledata.setValue(EndEntityProfile.AVAILTOKENISSUER, 0, availablehardtokenissuers);
              profiledata.setRequired(EndEntityProfile.AVAILTOKENISSUER, 0, true);    
            }
            
            value = request.getParameter(CHECKBOX_USE_PRINTING);
            if(value != null && value.equalsIgnoreCase(CHECKBOX_VALUE)){
                profiledata.setUsePrinting(true);
                
                value = request.getParameter(CHECKBOX_PRINTING);
                profiledata.setPrintingDefault(value != null && value.equalsIgnoreCase(CHECKBOX_VALUE));
                value = request.getParameter(CHECKBOX_REQUIRED_PRINTING);
                profiledata.setPrintingRequired(value != null && value.equalsIgnoreCase(CHECKBOX_VALUE));
                
                value = request.getParameter(SELECT_PRINTINGCOPIES);
                if(value != null){
                  profiledata.setPrintedCopies(Integer.parseInt(value));
                }
                value = request.getParameter(SELECT_PRINTINGPRINTERNAME);
                if(value != null){
                  profiledata.setPrinterName(value);
                } 
                
            }else{
                profiledata.setUsePrinting(false);
                profiledata.setPrintingDefault(false);
                profiledata.setPrintingRequired(false);
                profiledata.setPrintedCopies(1);
                profiledata.setPrinterName("");
                profiledata.setPrinterSVGData("");
                profiledata.setPrinterSVGFileName("");             
            }
            
               value = request.getParameter(CHECKBOX_USE_STARTTIME);
               if( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
                   value = request.getParameter(TEXTFIELD_STARTTIME);
                   profiledata.setValue(EndEntityProfile.STARTTIME, 0, (value != null && value.length() > 0) ? ejbcawebbean.getImpliedUTCFromISO8601OrRelative(value) : "");
                   profiledata.setUse(EndEntityProfile.STARTTIME, 0, true);
                   //profiledata.setRequired(EndEntityProfile.STARTTIME, 0, true);
                   value = request.getParameter(CHECKBOX_MODIFYABLE_STARTTIME);
                   profiledata.setModifyable(EndEntityProfile.STARTTIME, 0, (value != null && value.equalsIgnoreCase(CHECKBOX_VALUE)));
               } else {
                   profiledata.setValue(EndEntityProfile.STARTTIME, 0, "");
                   profiledata.setUse(EndEntityProfile.STARTTIME, 0, false);
               }
               value = request.getParameter(CHECKBOX_USE_ENDTIME);
               if( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
                   value = request.getParameter(TEXTFIELD_ENDTIME);
                   profiledata.setValue(EndEntityProfile.ENDTIME, 0, (value != null && value.length() > 0) ? ejbcawebbean.getImpliedUTCFromISO8601OrRelative(value) : "");
                   profiledata.setUse(EndEntityProfile.ENDTIME, 0, true);
                   //profiledata.setRequired(EndEntityProfile.ENDTIME, 0, true);
                   value = request.getParameter(CHECKBOX_MODIFYABLE_ENDTIME);
                   profiledata.setModifyable(EndEntityProfile.ENDTIME, 0, (value != null && value.equalsIgnoreCase(CHECKBOX_VALUE)));
               } else {
                   profiledata.setValue(EndEntityProfile.ENDTIME, 0, "");
                   profiledata.setUse(EndEntityProfile.ENDTIME, 0, false);
               }
    
               value = request.getParameter(CHECKBOX_USE_ALLOWEDRQUESTS);
               if( value != null && value.equalsIgnoreCase(CHECKBOX_VALUE) ) {
                   value = request.getParameter(SELECT_ALLOWEDREQUESTS);
                   if( value != null ) {
                       profiledata.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, value);
                   }
                   profiledata.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, true);
               } else {
                   profiledata.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, false);
               }
    
            if(request.getParameter(BUTTON_DELETESUBJECTDN) != null){  
              numberofsubjectdnfields = profiledata.getSubjectDNFieldOrderLength();
              int pointer = 0;
              for(int i=0; i < numberofsubjectdnfields; i++){
                if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SELECTSUBJECTDN + i))){
                  fielddata = profiledata.getSubjectDNFieldsInOrder(pointer);  
                  profiledata.removeField(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                }
                else
                  pointer++;
              }                          
            }
            if(request.getParameter(BUTTON_ADDSUBJECTDN) != null){             
              value = request.getParameter(SELECT_ADDSUBJECTDN);
              if(value!=null){
                profiledata.addField(value);             
              }                   
            }
            if(request.getParameter(BUTTON_DELETESUBJECTALTNAME) != null){             
              numberofsubjectaltnamefields = profiledata.getSubjectAltNameFieldOrderLength();
              int pointer = 0;
              for(int i=0; i < numberofsubjectaltnamefields; i++){
                if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SELECTSUBJECTALTNAME+i))){
                  fielddata = profiledata.getSubjectAltNameFieldsInOrder(pointer);  
                  profiledata.removeField(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                }
                else
                  pointer++;
              }             
            }
            if(request.getParameter(BUTTON_ADDSUBJECTALTNAME) != null){             
              value = request.getParameter(SELECT_ADDSUBJECTALTNAME);
              if(value!=null){
                profiledata.addField(value);                
              }                       
            }
            
            if(request.getParameter(BUTTON_DELETESUBJECTDIRATTR) != null){             
              numberofsubjectdirattrfields = profiledata.getSubjectDirAttrFieldOrderLength();
              int pointer = 0;
              for(int i=0; i < numberofsubjectdirattrfields; i++){
                if(ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_SELECTSUBJECTDIRATTR+i))){
                  fielddata = profiledata.getSubjectDirAttrFieldsInOrder(pointer);  
                  profiledata.removeField(fielddata[EndEntityProfile.FIELDTYPE],fielddata[EndEntityProfile.NUMBER]);
                }
                else
                  pointer++;
              }             
            }
            if(request.getParameter(BUTTON_ADDSUBJECTDIRATTR) != null){             
              value = request.getParameter(SELECT_ADDSUBJECTDIRATTR);
              if(value!=null){
                profiledata.addField(value);                
              }                       
            }
            
            includefile="endentityprofilepage.jspf";
            ejbcarabean.setTemporaryEndEntityProfile(profiledata);
    
          */

    /*
     * Add user notice.
     */
    /*       if(request.getParameter(BUTTON_ADD_NOTIFICATION) != null) {
               ejbcarabean.setTemporaryEndEntityProfileNotification(new UserNotification());
               ejbcarabean.setTemporaryEndEntityProfile(profiledata);
               includefile = "endentityprofilepage.jspf";
           }*/

    /*
     * Remove all user notices.
     */
    /*        if(request.getParameter(BUTTON_DELETEALL_NOTIFICATION) != null) {
                List<UserNotification> emptynot = new ArrayList<UserNotification>();
                profiledata.setUserNotifications(emptynot);
                ejbcarabean.setTemporaryEndEntityProfile(profiledata);
                includefile = "endentityprofilepage.jspf";
            } */

    /*
     * Remove/Edit user notice.
     */

    /*
            if (profiledata.getUserNotifications() != null &&
                    ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_SENDNOTIFICATION))) {
                boolean removed = false;
                final int numnots = profiledata.getUserNotifications().size();
                if(request.getParameter(BUTTON_DELETE_TEMPORARY_NOTIFICATION) != null) {
                    ejbcarabean.setTemporaryEndEntityProfileNotification(null);
                }
                for(int i = 0; i < numnots; i++) {
                    String delete = request.getParameter(BUTTON_DELETE_NOTIFICATION + i);
                    
                    if (request.getParameter(TEXTFIELD_NOTIFICATIONSENDER + NEWVALUE + i) == null) {
                        continue;
                    }
                    
                    // First, delete the old value
                    { // hide variables
                        UserNotification not = ejbcarabean.getNotificationForDelete(
                           request.getParameter(TEXTFIELD_NOTIFICATIONSENDER + OLDVALUE + i),
                           request.getParameter(TEXTFIELD_NOTIFICATIONRCPT + OLDVALUE + i),
                           request.getParameter(TEXTFIELD_NOTIFICATIONSUBJECT + OLDVALUE + i),
                           request.getParameter(TEXTAREA_NOTIFICATIONMESSAGE + OLDVALUE + i),
                           request.getParameterValues(SELECT_NOTIFICATIONEVENTS + OLDVALUE + i));
                        profiledata.removeUserNotification(not);
                    }
                    
                    if (delete != null) {
                        // Delete = don't create again.
                        // Stay at the profile page.
                        removed = true;
                    } else {
                        // Edit
                        UserNotification not = ejbcarabean.getNotificationForAdd(
                           request.getParameter(TEXTFIELD_NOTIFICATIONSENDER + NEWVALUE + i),
                           request.getParameter(TEXTFIELD_NOTIFICATIONRCPT + NEWVALUE + i),
                           request.getParameter(TEXTFIELD_NOTIFICATIONSUBJECT + NEWVALUE + i),
                           request.getParameter(TEXTAREA_NOTIFICATIONMESSAGE + NEWVALUE + i),
                           request.getParameterValues(SELECT_NOTIFICATIONEVENTS + NEWVALUE + i));
                        profiledata.addUserNotification(not);
                    }
                }         
                if (removed) {
                  ejbcarabean.setTemporaryEndEntityProfile(profiledata);
                  ejbcarabean.setTemporaryEndEntityProfileNotification(null);
                  includefile = "endentityprofilepage.jspf";
                }
            }
    
            */
    /*
     * Add new notification
     */

    /*
            String sender = request.getParameter(TEXTFIELD_NOTIFICATIONSENDER);
            if ((sender != null) && (sender.length() > 0) &&
                    ejbcarabean.getEndEntityParameter(request.getParameter(CHECKBOX_USE_SENDNOTIFICATION))) {
                UserNotification not = new UserNotification();
                not.setNotificationSender(sender);
                not.setNotificationSubject(request.getParameter(TEXTFIELD_NOTIFICATIONSUBJECT));
                not.setNotificationMessage(request.getParameter(TEXTAREA_NOTIFICATIONMESSAGE));
                String rcpt = request.getParameter(TEXTFIELD_NOTIFICATIONRCPT);
                if ( (rcpt == null) || (rcpt.length() == 0) ) {
                    // Default value if nothing is entered is users email address
                    rcpt = UserNotification.RCPT_USER;
                }
                not.setNotificationRecipient(rcpt);
                String[] val = request.getParameterValues(SELECT_NOTIFICATIONEVENTS);
                String events = null;
                for (String v : val) {
                   if (events == null) {
                      events = v;
                   } else {
                      events = events + ";"+v;
                   }
                }
                not.setNotificationEvents(events);
                profiledata.addUserNotification(not);
            }
            
            if(request.getParameter(BUTTON_SAVE) != null && editerrors.isEmpty()){             
                ejbcarabean.changeEndEntityProfile(profile,profiledata);
                ejbcarabean.setTemporaryEndEntityProfile(null);
                ejbcarabean.setTemporaryEndEntityProfileNotification(null);
                includefile="endentityprofilespage.jspf"; 
                savedprofilesuccess = true;
            }
            
            if(request.getParameter(BUTTON_UPLOADTEMPLATE) != null){
                  includefile="uploadtemplate.jspf";
             }
          }
          if(request.getParameter(BUTTON_CANCEL) != null){
             // Don't save changes.
            ejbcarabean.setTemporaryEndEntityProfile(null);
            ejbcarabean.setTemporaryEndEntityProfileNotification(null);
            includefile="endentityprofilespage.jspf";
          }
     }
    }
    
    */
    //Stop import from jsp file

    // Random variables from jsp:

    /*  
      static final String ACTION                        = "action";
      static final String ACTION_EDIT_PROFILES          = "editprofiles";
      static final String ACTION_EDIT_PROFILE           = "editprofile";
      static final String ACTION_UPLOADTEMP             = "uploadtemp";
      static final String ACTION_IMPORT_EXPORT           = "importexportprofiles";
    
      
    
    
      static final String BUTTON_EDIT_PROFILE      = "buttoneditprofile"; 
      static final String BUTTON_DELETE_PROFILE    = "buttondeleteprofile";
      static final String BUTTON_ADD_PROFILE       = "buttonaddprofile"; 
      static final String BUTTON_RENAME_PROFILE    = "buttonrenameprofile";
      static final String BUTTON_CLONE_PROFILE     = "buttoncloneprofile";
    
      static final String SELECT_PROFILE           = "selectprofile";
      static final String TEXTFIELD_PROFILENAME    = "textfieldprofilename";
      static final String TEXTFIELD_EXPORT_DESTINATION     = "textfieldexportdestination";
      static final String HIDDEN_PROFILENAME       = "hiddenprofilename";
      static final String BUTTON_IMPORT_PROFILES   = "buttonimportprofiles";
      static final String BUTTON_EXPORT_PROFILES     = "buttonexportprofiles";
     
    
      static final String BUTTON_SAVE              = "buttonsave";
      static final String BUTTON_CANCEL            = "buttoncancel";
      static final String BUTTON_UPLOADTEMPLATE    = "buttonuploadtemplate";
      static final String BUTTON_UPLOADFILE        = "buttonuploadfile";
     
      static final String BUTTON_ADD_NOTIFICATION    = "buttonaddnotification";
      static final String BUTTON_ADD_ANOTHER_NOTIFICATION = "buttonaddanothernotification";
      static final String BUTTON_DELETEALL_NOTIFICATION = "buttondeleteallnotification";
      static final String BUTTON_DELETE_NOTIFICATION = "buttondeleltenotification";
      static final String BUTTON_DELETE_TEMPORARY_NOTIFICATION = "buttondeletetemporarynotification";
     
      static final String TEXTFIELD_USERNAME             = "textfieldusername";
      static final String TEXTFIELD_PASSWORD             = "textfieldpassword";
      static final String TEXTFIELD_MINPWDSTRENGTH       = "textfieldminpwdstrength";
      static final String TEXTFIELD_SUBJECTDN            = "textfieldsubjectdn";
      static final String TEXTFIELD_VALIDATION_SUBJECTDN = "textfieldsubjectdnvalidation";
      static final String TEXTFIELD_VALIDATION_SUBJECTALTNAME = "textfieldsubjectaltnamevalidation";
      static final String TEXTFIELD_SUBJECTALTNAME       = "textfieldsubjectaltname";
      static final String TEXTFIELD_SUBJECTDIRATTR       = "textfieldsubjectdirattr";
      static final String TEXTFIELD_EMAIL                = "textfieldemail";
      static final String TEXTFIELD_NOTIFICATIONSENDER   = "textfieldnotificationsender";
      static final String TEXTFIELD_NOTIFICATIONRCPT     = "textfieldnotificationrcpt";
      static final String TEXTFIELD_NOTIFICATIONSUBJECT  = "textfieldnotificationsubject";
      static final String SELECT_NOTIFICATIONEVENTS      = "selectnotificationevents";
      static final String TEXTFIELD_STARTTIME            = "textfieldstarttime";
      static final String TEXTFIELD_ENDTIME              = "textfieldendtime";
      static final String TEXTFIELD_MAXFAILEDLOGINS      = "textfieldmaxfailedlogins";
     
      static final String TEXTAREA_NOTIFICATIONMESSAGE  = "textareanotificationmessage";
      
      static final String CHECKBOX_CLEARTEXTPASSWORD          = "checkboxcleartextpassword";
      static final String CHECKBOX_KEYRECOVERABLE             = "checkboxkeyrecoverable";
      static final String CHECKBOX_REUSECERTIFICATE           = "checkboxreusecertificate";
      static final String CHECKBOX_REVERSEFIELDCHECKS         = "checkboxreversefieldchecks";
      static final String CHECKBOX_CARDNUMBER                 = "checkboxcardnumber";
      static final String CHECKBOX_SENDNOTIFICATION           = "checkboxsendnotification";
      static final String CHECKBOX_PRINTING                   = "checkboxprinting";
      static final String CHECKBOX_USE_STARTTIME              = "checkboxsusetarttime";
      static final String CHECKBOX_REQUIRED_STARTTIME         = "checkboxrelativestarttime";
      static final String CHECKBOX_MODIFYABLE_STARTTIME       = "checkboxmodifyablestarttime";
      static final String CHECKBOX_USE_ENDTIME                = "checkboxuseendtime";
      static final String CHECKBOX_REQUIRED_ENDTIME           = "checkboxrelativeendtime";
      static final String CHECKBOX_MODIFYABLE_ENDTIME         = "checkboxmodifyableendtime";
      static final String CHECKBOX_ALLOW_MERGEDN_WEBSERVICES = "checkboxallowmergednwebservices";
      
      static final String CHECKBOX_REQUIRED_PASSWORD          = "checkboxrequiredpassword";
      static final String CHECKBOX_REQUIRED_CLEARTEXTPASSWORD = "checkboxrequiredcleartextpassword";
      static final String CHECKBOX_REQUIRED_SUBJECTDN         = "checkboxrequiredsubjectdn";
      static final String CHECKBOX_REQUIRED_SUBJECTALTNAME    = "checkboxrequiredsubjectaltname";
      static final String CHECKBOX_REQUIRED_SUBJECTDIRATTR    = "checkboxrequiredsubjectdirattr";
      static final String CHECKBOX_REQUIRED_EMAIL             = "checkboxrequiredemail";
      static final String CHECKBOX_REQUIRED_CARDNUMBER        = "checkboxrequiredcardnumber";
      static final String CHECKBOX_REQUIRED_NC_PERMITTED      = "checkboxrequiredncpermitted";
      static final String CHECKBOX_REQUIRED_NC_EXCLUDED       = "checkboxrequiredncexcluded";
      static final String CHECKBOX_REQUIRED_SENDNOTIFICATION  = "checkboxrequiredsendnotification";
      static final String CHECKBOX_REQUIRED_KEYRECOVERABLE    = "checkboxrequiredkeyrecoverable";
      static final String CHECKBOX_REQUIRED_PRINTING          = "checkboxrequiredprinting";
      static final String CHECKBOX_REQUIRED_MAXFAILEDLOGINS   = "checkboxrequiredmaxfailedlogins";
    
      public static final String CHECKBOX_AUTOGENERATED_USERNAME     = "checkboxautogeneratedusername";
      static final String CHECKBOX_MODIFYABLE_PASSWORD          = "checkboxmodifyablepassword";
      static final String CHECKBOX_MODIFYABLE_SUBJECTDN         = "checkboxmodifyablesubjectdn";
      static final String CHECKBOX_MODIFYABLE_SUBJECTALTNAME    = "checkboxmodifyablesubjectaltname";
      static final String CHECKBOX_MODIFYABLE_SUBJECTDIRATTR    = "checkboxmodifyablesubjectdirattr";
      static final String CHECKBOX_MODIFYABLE_EMAIL             = "checkboxmodifyableemail";
      static final String CHECKBOX_MODIFYABLE_ISSUANCEREVOCATIONREASON = "checkboxmodifyableissuancerevocationreason";
      static final String CHECKBOX_MODIFYABLE_MAXFAILEDLOGINS   = "checkboxmodifyablemaxfailedlogins";
      
      static final String CHECKBOX_VALIDATION_SUBJECTDN  = "checkboxvalidationsubjectdn";
      static final String CHECKBOX_VALIDATION_SUBJECTALTNAME  = "checkboxvalidationsubjectaltname";
      static final String LABEL_VALIDATION_SUBJECTDN     = "labelvalidationsubjectdn";
      static final String LABEL_VALIDATION_SUBJECTALTNAME     = "labelvalidationsubjectaltname";
    
      static final String CHECKBOX_USE_CARDNUMBER        = "checkboxusecardnumber";
      static final String CHECKBOX_USE_PASSWORD          = "checkboxusepassword";
      static final String CHECKBOX_USE_CLEARTEXTPASSWORD = "checkboxusecleartextpassword";
      static final String CHECKBOX_USE_SUBJECTDN         = "checkboxusesubjectdn";
      static final String CHECKBOX_USE_SUBJECTALTNAME    = "checkboxusesubjectaltname";
      static final String CHECKBOX_USE_EMAIL             = "checkboxuseemail";
      static final String CHECKBOX_USE_KEYRECOVERABLE    = "checkboxusekeyrecoverable";
      static final String CHECKBOX_USE_SENDNOTIFICATION  = "checkboxusesendnotification";
      static final String CHECKBOX_USE_HARDTOKENISSUERS  = "checkboxusehardtokenissuers";
      static final String CHECKBOX_USE_PRINTING          = "checkboxuseprinting";
      static final String CHECKBOX_USE_ALLOWEDRQUESTS    = "checkboxuseallowedrequests";
      static final String CHECKBOX_USE_ISSUANCEREVOCATIONREASON = "checkboxuseissuancerevocationreason";
      static final String CHECKBOX_USE_MAXFAILEDLOGINS   = "checkboxusemaxfailedlogins";
      static final String CHECKBOX_USE_CERTSERIALNR      = "checkboxusecertserialonr";
      static final String CHECKBOX_USE_NC_PERMITTED      = "checkboxusencpermitted";
      static final String CHECKBOX_USE_NC_EXCLUDED       = "checkboxusencexcluded";
      static final String CHECKBOX_USE_EXTENSIONDATA     = "checkboxuseextensiondata";
      
      static final String RADIO_MAXFAILEDLOGINS               = "radiomaxfailedlogins";
      static final String RADIO_MAXFAILEDLOGINS_VAL_UNLIMITED = "unlimited";
      static final String RADIO_MAXFAILEDLOGINS_VAL_SPECIFIED = "specified";
      
      static final String SELECT_AUTOPASSWORDTYPE               = "selectautopasswordtype";
      static final String SELECT_AUTOPASSWORDLENGTH             = "selectautopasswordlength";
    
      static final String SELECT_ISSUANCEREVOCATIONREASON       = "selectissuancerevocationreason";
      
      static final String SELECT_DEFAULTCERTPROFILE             = "selectdefaultcertprofile";
      static final String SELECT_AVAILABLECERTPROFILES          = "selectavailablecertprofiles";
    
      static final String SELECT_DEFAULTTOKENTYPE               = "selectdefaulttokentype";
      static final String SELECT_AVAILABLETOKENTYPES            = "selectavailabletokentypes";
    
    
      static final String SELECT_DEFAULTCA                      = "selectdefaultca";
      static final String SELECT_AVAILABLECAS                   = "selectavailablecas";
    
      static final String SELECT_DEFAULTHARDTOKENISSUER         = "selectdefaulthardtokenissuer";
      static final String SELECT_AVAILABLEHARDTOKENISSUERS      = "selectavailablehardtokenissuers";
    
      static final String SELECT_PRINTINGPRINTERNAME            = "selectprinteringprintername";
      static final String SELECT_PRINTINGCOPIES                 = "selectprinteringcopies";
    
      static final String SELECT_ALLOWEDREQUESTS                = "selectallowedrequests";
    
      static final String SELECT_ADDSUBJECTDN                   = "selectaddsubjectdn";
      static final String BUTTON_DELETESUBJECTDN                = "buttondeletesubjectdn";
      static final String BUTTON_ADDSUBJECTDN                   = "buttonaddsubjectdn";
      static final String CHECKBOX_SELECTSUBJECTDN              = "checkboxselectsubjectdn";
      static final String SELECT_ADDSUBJECTALTNAME              = "selectaddsubjectaltname";
      static final String BUTTON_DELETESUBJECTALTNAME           = "buttondeletesubjectaltname";
      static final String BUTTON_ADDSUBJECTALTNAME              = "buttonaddsubjectaltname";
      static final String CHECKBOX_SELECTSUBJECTALTNAME         = "checkboxselectsubjectaltname";
    
      static final String SELECT_ADDSUBJECTDIRATTR              = "selectaddsubjectdirattr";
      static final String BUTTON_DELETESUBJECTDIRATTR           = "buttondeletesubjectdirattr";
      static final String BUTTON_ADDSUBJECTDIRATTR              = "buttonaddsubjectdirattr";
      static final String CHECKBOX_SELECTSUBJECTDIRATTR         = "checkboxselectsubjectdirattr";
      static final String SELECT_TYPE                         = "selecttype";
      
      static final String OLDVALUE                              = "_oldvalue";
      static final String NEWVALUE                              = "_newvalue";
      
      static final String FILE_IMPORTFILE                        = "fileimportfile";
      
      public static final String FILE_TEMPLATE             = "filetemplate";
    
    */
}
