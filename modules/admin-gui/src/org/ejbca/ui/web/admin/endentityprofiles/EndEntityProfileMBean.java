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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
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

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;

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
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;

import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

import org.ejbca.ui.web.admin.hardtokeninterface.HardTokenInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.admin.rainterface.ViewEndEntityHelper;

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

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;

    static final String CHECKBOX_VALUE = EndEntityProfile.TRUE;

    private EndEntityProfilesMBean endEntityProfilesMBean;
    private EjbcaWebBean ejbcaWebBean = getEjbcaWebBean();
    private CAInterfaceBean caBean = new CAInterfaceBean();
    private RAInterfaceBean raBean = new RAInterfaceBean();
    private HardTokenInterfaceBean tokenBean = new HardTokenInterfaceBean();
    private EndEntityProfile profiledata;
    private int profileId;
    private final Map<String, String> editerrors = new HashMap<String, String>();

    //POST CONSTRUCT
    @PostConstruct
    private void postConstruct() {
        final HttpServletRequest req = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            ejbcaWebBean.initialize(req, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
            caBean.initialize(ejbcaWebBean);
            raBean.initialize(req, ejbcaWebBean);
            tokenBean.initialize(req, ejbcaWebBean);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        profileId = endEntityProfilesMBean.getSelectedEndEntityProfileId().intValue();
        profiledata = endEntityProfileSession.getEndEntityProfile(profileId);
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

    // PASSWORD, USERNAME AND EMAIL

    // 
    public void setUseAutoGeneratedUserName(boolean autoGeneratedUserName) {
        profiledata.setModifyable(EndEntityProfile.USERNAME, 0, autoGeneratedUserName);
    }

    public boolean getUseAutoGeneratedUserName() {
        return profiledata.isAutoGeneratedUsername();
    }

    // 
    public String getPassword() {
        return profiledata.getValue(EndEntityProfile.PASSWORD, 0);
    }

    // 
    public void setPassword(String password) {
        profiledata.setValue(EndEntityProfile.PASSWORD, 0, password);
    }

    //
    public boolean getPasswordRequired() {
        return profiledata.isPasswordRequired();
    }

    // 
    public void setPasswordRequired(boolean passwordRequired) {
        profiledata.setRequired(EndEntityProfile.PASSWORD, 0, passwordRequired);
    }

    // 
    public boolean getAutoGeneratedPassword() {
        return !profiledata.getUse(EndEntityProfile.PASSWORD, 0);
    }

    //
    public void setAutoGeneratedPassword(boolean autoGenerate) {
        if (autoGenerate) {
            setPasswordRequired(false);
            profiledata.setUse(EndEntityProfile.PASSWORD, 0, false);
        } else {
            profiledata.setUse(EndEntityProfile.PASSWORD, 0, true);
        }
    }

    //
    public String getCurrentPasswordType() {
        return profiledata.getAutoGeneratedPasswdType();
    }

    //
    public void setCurrentPasswordType(String passwordType) {
        profiledata.setValue(EndEntityProfile.AUTOGENPASSWORDTYPE, 0, passwordType);
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

    //
    public List<SelectItem> getPasswordLen() {
        final List<SelectItem> pwdLenListReturned = new ArrayList<>();
        Integer len = 4;
        for (; len < 17; len++) {//possible values: 4-16, hard coded here?
            pwdLenListReturned.add(new SelectItem(len.toString(), len.toString()));
        }
        return pwdLenListReturned;
    }

    // 
    public void setCurrentPasswordLen(String len) {
        profiledata.setValue(EndEntityProfile.AUTOGENPASSWORDLENGTH, 0, len);
    }

    // 
    public String getCurrentPasswordLen() {
        //return new Integer(profiledata.getAutoGeneratedPasswdLength()).toString();
        Integer pwdLen = profiledata.getAutoGeneratedPasswdLength();
        return pwdLen.toString();
    }

    // 
    public boolean getUseMaxFailLogins() {
        return profiledata.getMaxFailedLoginsUsed();
    }

    //
    public void setUseMaxFailLogins(boolean useMaxFailLogins) {
        profiledata.setUse(EndEntityProfile.MAXFAILEDLOGINS, 0, useMaxFailLogins);
    }

    // 
    public boolean getFailedLoginsModifyable() {
        return profiledata.getMaxFailedLoginsModifiable();
    }

    //
    public void setFailedLoginsModifyable(boolean modifyable) {
        profiledata.setModifyable(EndEntityProfile.MAXFAILEDLOGINS, 0, modifyable);
    }

    // 
    public String getMaxFailedLogins() {
        String maxString = profiledata.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0);
        if (maxString.equals("-1")) {
            return "";
        }
        return maxString;
    }

    //
    public void setMaxFailedLogins(String maxFail) {
        profiledata.setValue(EndEntityProfile.MAXFAILEDLOGINS, 0, maxFail);
    }

    public boolean getMaxFailLoginsUnlimited() {
        return profiledata.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0).equals("-1");
    }

    public void setMaxFailLoginsUnlimited(boolean unlimited) {
        if (unlimited) {
            profiledata.setValue(EndEntityProfile.MAXFAILEDLOGINS, 0, "-1");
        } else {
            profiledata.setValue(EndEntityProfile.MAXFAILEDLOGINS, 0, getMaxFailedLogins());
        }
    }

    //
    public boolean getBatchGenerationUse() {
        return profiledata.getUse(EndEntityProfile.CLEARTEXTPASSWORD, 0);
    }

    public void setBatchGenerationUse(boolean useBatchGeneration) {
        profiledata.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, useBatchGeneration);
    }

    //
    public boolean getBatchGenerationDefault() {
        return profiledata.getValue(EndEntityProfile.CLEARTEXTPASSWORD, 0).equals(EndEntityProfile.TRUE) && getBatchGenerationUse();
    }

    public void setBatchGenerationDefault(boolean batchGenerationDefault) { // Verify, temporary for now
        if (batchGenerationDefault) {
            profiledata.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);
        }
    }

    //
    public boolean getBatchGenerationRequired() {
        return profiledata.isRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0) && getBatchGenerationUse();
    }

    public void setBatchGenerationRequired(boolean batchGenerationRequired) {
        profiledata.setRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0, batchGenerationRequired);
    }

    //
    public boolean getUseEmail() {
        return profiledata.getUse(EndEntityProfile.EMAIL, 0);
    }

    //
    public void setUseEmail(boolean useEmail) {
        profiledata.setUse(EndEntityProfile.EMAIL, 0, useEmail);
    }

    // temporary, verify... 
    public String getEmail() {
        String email = "";
        if (profiledata.getValue(EndEntityProfile.EMAIL, 0) != null && getUseEmail()) {
            email = profiledata.getValue(EndEntityProfile.EMAIL, 0);
        }
        return email;
    }

    // as above...
    public void setEmail(String email) {
        if (getUseEmail()) {
            profiledata.setValue(EndEntityProfile.EMAIL, 0, email);
        }
    }

    //
    public boolean isEmailRequired() {
        return profiledata.getEmailDomainRequired();
    }

    //
    public void setEmailRequired(boolean emailRequired) {
        profiledata.setRequired(EndEntityProfile.EMAIL, 0, emailRequired);
    }

    //
    public boolean isEmailModifyable() {
        return profiledata.getEmailDomainModifiable();
    }

    //
    public void setEmailModifyable(boolean emailModifyable) {
        profiledata.setModifyable(EndEntityProfile.EMAIL, 0, emailModifyable);
    }

    // DIRECTIVES

    // SUBJECT DN ATTRIBUTES

    //
    public List<SelectItem> getSubjectDNAttributes() {
        final List<SelectItem> attributesReturned = new ArrayList<>();
        String attribute;
        String attributeReturned;
        String[] attributeString = EndEntityProfile.getSubjectDNProfileFields();
        int stringElement;
        for (stringElement = 0; stringElement < attributeString.length; stringElement++) {
            attribute = attributeString[stringElement];
            attributeReturned = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileName(attribute));
            attributesReturned.add(new SelectItem(attribute, attributeReturned));
        }
        return attributesReturned;
    }

    // testing...
    private String currentSubjectDNAttribute;
    private String addedSubjectDNAttribute;

    // 
    public String getCurrentSubjectDNAttribute() {
        return currentSubjectDNAttribute;
    }

    public void setCurrentSubjectDNAttribute(String attribute) {
        currentSubjectDNAttribute = attribute;
    }

    // temp
    public String addSubjectDNAttribute() {
        addedSubjectDNAttribute = new String(currentSubjectDNAttribute); // need to fetch the value from the selected component here instead...
        profiledata.addField(addedSubjectDNAttribute);
        return ""; // remove
    }

    // if to write DN text field in gui 
    public boolean emailField(String fieldProcessing) {
        boolean returnValue;
        if (!fieldProcessing.contains("E-mail")) {
            returnValue = true;
        } else {
            returnValue = false;
        }
        return returnValue;
    }

    // New SDN component object, currently testing only
    public class SubjectDnComponent implements Serializable {
        private static final long serialVersionUID = 1L;
        private int[] componentField;
        private String componentName;
        private String componentValue;
        private boolean componentIsRequired;
        private boolean componentIsModifyable;

        public SubjectDnComponent(String componentName, boolean componentIsRequired, boolean componentIsModifyable, boolean componentValueValidation,
                int[] componentField, String componentValue, String componentValidationString) {
            this.componentName = componentName;
            this.componentField = componentField;
            this.componentIsRequired = componentIsRequired;
            this.componentIsModifyable = componentIsModifyable;
            this.componentValue = componentValue;
        }

        public boolean isEmailField() {
            return componentName.contains("E-mail");
        }

        public String getComponentName() {
            return componentName;
        }

        public void setComponentName(String componentName) {
            this.componentName = componentName;
        }

        public String getComponentValue() {
            componentValue = profiledata.getValue(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]);
            return componentValue;
        }

        public void setComponentValue(String value) {
            componentValue = value;
            // Test validation begin
            if (!EndEntityProfile.isFieldOfType(componentField[EndEntityProfile.FIELDTYPE], DnComponents.DNEMAILADDRESS)) {
                if ((value == null) || (value.trim().equals("")) && componentIsModifyable == false && componentIsRequired == true) {
                    editerrors.put(componentName, ejbcaWebBean.getText("SUBJECTDNFIELDEMPTY", true) + ejbcaWebBean.getText(" " + "DN_PKIX_".concat(componentName), true));
                } else {
                    profiledata.setValue(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], this.componentValue);
                }
            } else {
                if ((value == null) || (value.trim().equals("")) && componentIsModifyable == false && componentIsRequired == true) {
                    editerrors.put(componentName, ejbcaWebBean.getText("SUBJECTDNEMAILEMPTY", true));
                } else {
                    // Test validation end 
                    profiledata.setValue(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], this.componentValue);
                }
            }
        }

        public int[] getComponentField() {
            return componentField;
        }

        public void getComponentField(int[] componentField) {
            this.componentField = componentField;
        }

        public boolean getComponentIsRequired() {
            return componentIsRequired;
        }

        public void setComponentIsRequired(boolean componentIsRequired) {
            this.componentIsRequired = componentIsRequired;
            profiledata.setRequired(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentIsRequired);
        }

        public boolean getComponentIsModifyable() {
            return componentIsModifyable;
        }

        public void setComponentIsModifyable(boolean componentIsModifyable) {
            this.componentIsModifyable = componentIsModifyable;
            profiledata.setModifyable(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentIsModifyable);

        }

        public boolean getComponentValueValidation() {
            return null != profiledata.getValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]);
        }

        // ..temporary
        public void setComponentValueValidation(boolean componentValueValidation) {
            if (componentValueValidation) {
                if (profiledata.getValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]) == null) {
                    profiledata.setValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], new LinkedHashMap<String, Serializable>());
                }
            } else {
                profiledata.setValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], null);
            }
        }

        public String getComponentValidationString() {
            if (getComponentValueValidation()) {
                return (String) profiledata.getValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]).get(RegexFieldValidator.class.getName());
            } else {
                return "";
            }
        }

        public void setComponentValidationString(String componentValidationString) {
            final LinkedHashMap<String, Serializable> validation = raBean.getValidationFromRegexp(componentValidationString);
            profiledata.setValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], validation);
        }

    }

    public List<SubjectDnComponent> subjectDnComponentList;

    public List<SubjectDnComponent> getSubjectDnComponentList() {
        subjectDnComponentList = new ArrayList<SubjectDnComponent>();
        List<int[]> fielddatalist = new ArrayList<int[]>();
        int numberofsubjectdnfields = profiledata.getSubjectDNFieldOrderLength();
        for (int i = 0; i < numberofsubjectdnfields; i++) {
            fielddatalist.add(profiledata.getSubjectDNFieldsInOrder(i));
        }
        for (int[] temp : fielddatalist) {
            boolean required = profiledata.isRequired(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            boolean modifyable = profiledata.isModifyable(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            // ..replace?
            boolean validation = null != profiledata.getValidation(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            String value = profiledata.getValue(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            String validationString;
            if (validation) {
                validationString = (String) profiledata.getValidation(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]).get(RegexFieldValidator.class.getName());
            } else {
                validationString = "";
            }
            subjectDnComponentList.add(new SubjectDnComponent(ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(temp[EndEntityProfile.FIELDTYPE])), 
                    required, modifyable, validation, temp, value, validationString));
        }
        return subjectDnComponentList;
    }

    // OTHER SUBJECT ATTRIBUTES

    //
    public class SubjectAltNameComponent implements Serializable {
        private static final long serialVersionUID = 1L;
        private int[] componentField;
        private String componentName;
        private String componentValue;
        private boolean componentIsRequired;
        private boolean componentIsModifyable;

        public SubjectAltNameComponent(String componentName, boolean componentIsRequired, boolean componentIsModifyable,
                boolean componentValueValidation, int[] componentField, String componentValue, String componentValidationString) {
            this.componentName = componentName;
            this.componentField = componentField;
            this.componentIsRequired = componentIsRequired;
            this.componentIsModifyable = componentIsModifyable;
            this.componentValue = componentValue;
        }

        public String getComponentName() {
            return componentName;
        }

        public void setComponentName(String componentName) {
            this.componentName = componentName;
        }

        public String getComponentValue() {
            return componentValue;
        }

        public void setComponentValue(String componentValue) {
            this.componentValue = componentValue;
            profiledata.setValue(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentValue);
        }

        public int[] getComponentField() {
            return componentField;
        }

        public void getComponentField(int[] componentField) {
            this.componentField = componentField;
        }

        public boolean getComponentIsRequired() {
            return componentIsRequired;
        }

        public void setComponentIsRequired(boolean componentIsRequired) {
            this.componentIsRequired = componentIsRequired;
            profiledata.setRequired(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentIsRequired);
        }

        public boolean getComponentIsModifyable() {
            return componentIsModifyable;
        }

        public void setComponentIsModifyable(boolean componentIsModifyable) {
            this.componentIsModifyable = componentIsModifyable;
            profiledata.setModifyable(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentIsModifyable);

        }

        public boolean getComponentValueValidation() {
            return null != profiledata.getValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]);
        }

        // ..temporary
        public void setComponentValueValidation(boolean componentValueValidation) {
            if (componentValueValidation) {
                if (profiledata.getValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]) == null) {
                    profiledata.setValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER],
                            new LinkedHashMap<String, Serializable>());
                }
            } else {
                profiledata.setValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], null);
            }
        }

        public String getComponentValidationString() {
            if (getComponentValueValidation()) {
                return (String) profiledata.getValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER]).get(RegexFieldValidator.class.getName());
            } else {
                return "";
            }
        }

        public void setComponentValidationString(String componentValidationString) {
            final LinkedHashMap<String, Serializable> validation = raBean.getValidationFromRegexp(componentValidationString);
            profiledata.setValidation(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], validation);
        }
    }

    //
    public List<SelectItem> getSubjectAltNameTypes() {
        final List<SelectItem> subjectAltNamesReturned = new ArrayList<>();
        String subjectAltName;
        String subjectAltNameReturned;
        String[] attributeString = EndEntityProfile.getSubjectAltnameProfileFields();
        Integer stringElement;
        for (stringElement = 0; stringElement < attributeString.length; stringElement++) {
            subjectAltName = attributeString[stringElement.intValue()];
            if (EndEntityProfile.isFieldImplemented(subjectAltName)) {
                subjectAltNameReturned = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileName(subjectAltName));
                subjectAltNamesReturned.add(new SelectItem(subjectAltName, subjectAltNameReturned));
            }
        }
        return subjectAltNamesReturned;
    }

    private String currentSubjectAltName;
    private String addedSubjectAltName;

    public String addSubjectAltName() {
        addedSubjectAltName = new String(currentSubjectAltName); // I need to fetch the value from the selected component here instead...
        profiledata.addField(addedSubjectAltName);
        return "";// remove
    }

    // temp value atm
    public String getCurrentSubjectAltNameType() {
        return currentSubjectAltName;
    }

    // temp value atm
    public void setCurrentSubjectAltNameType(String subjectAltNameType) {
        currentSubjectAltName = subjectAltNameType;
    }

    //
    public List<SubjectAltNameComponent> getSubjectAltNameComponent() {
        List<SubjectAltNameComponent> subjectAltNameComponentList = new ArrayList<SubjectAltNameComponent>();
        List<int[]> fielddatalist = new ArrayList<int[]>();
        int numberOfSubjectAltNameFields = profiledata.getSubjectAltNameFieldOrderLength();
        for (int i = 0; i < numberOfSubjectAltNameFields; i++) {
            fielddatalist.add(profiledata.getSubjectAltNameFieldsInOrder(i));
        }
        for (int[] temp : fielddatalist) {
            boolean required = profiledata.isRequired(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            boolean modifyable = profiledata.isModifyable(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            // replace?
            boolean validation = null != profiledata.getValidation(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            String value = profiledata.getValue(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            String validationString;
            if (validation) {
                validationString = (String) profiledata.getValidation(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]).get(RegexFieldValidator.class.getName());
            } else {
                validationString = "";
            }
            subjectAltNameComponentList.add(new SubjectAltNameComponent(ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(temp[EndEntityProfile.FIELDTYPE])), 
                    required, modifyable, validation, temp, value, validationString));
        }
        return subjectAltNameComponentList;
    }

    //
    public class SubjectDirectoryAttributesComponent implements Serializable {
        private static final long serialVersionUID = 1L;
        private int[] componentField;
        private String componentName;
        private String componentValue;
        private boolean componentIsRequired;
        private boolean componentIsModifyable;

        public SubjectDirectoryAttributesComponent(String componentName, boolean componentIsRequired, boolean componentIsModifyable,
                int[] componentField, String componentValue) {
            this.componentName = componentName;
            this.componentField = componentField;
            this.componentIsRequired = componentIsRequired;
            this.componentIsModifyable = componentIsModifyable;
            this.componentValue = componentValue;
        }

        public String getComponentName() {
            return componentName;
        }

        public void setComponentName(String componentName) {
            this.componentName = componentName;
        }

        public String getComponentValue() {
            return componentValue;
        }

        public void setComponentValue(String componentValue) {
            this.componentValue = componentValue;
            profiledata.setValue(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentValue);
        }

        public int[] getComponentField() {
            return componentField;
        }

        public void getComponentField(int[] componentField) {
            this.componentField = componentField;
        }

        public boolean getComponentIsRequired() {
            return componentIsRequired;
        }

        public void setComponentIsRequired(boolean componentIsRequired) {
            this.componentIsRequired = componentIsRequired;
            profiledata.setRequired(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentIsRequired);
        }

        public boolean getComponentIsModifyable() {
            return componentIsModifyable;
        }

        public void setComponentIsModifyable(boolean componentIsModifyable) {
            this.componentIsModifyable = componentIsModifyable;
            profiledata.setModifyable(componentField[EndEntityProfile.FIELDTYPE], componentField[EndEntityProfile.NUMBER], componentIsModifyable);

        }
    }

    //
    public List<SelectItem> getSubjectDirectoryAttributes() {
        final List<SelectItem> subjectDirectoryAttributesReturned = new ArrayList<>();
        String subjectDirectoryAttribute;
        String subjectDirectoryAttributeReturned;
        String[] attributeString = EndEntityProfile.getSubjectDirAttrProfileFields();
        Integer stringElement;
        for (stringElement = 0; stringElement < attributeString.length; stringElement++) {
            subjectDirectoryAttribute = attributeString[stringElement.intValue()];
            subjectDirectoryAttributeReturned = ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileName(subjectDirectoryAttribute));
            subjectDirectoryAttributesReturned.add(new SelectItem(subjectDirectoryAttribute, subjectDirectoryAttributeReturned));
        }
        return subjectDirectoryAttributesReturned;
    }

    private String currentSubjectDirectoryAttribute;
    private String addedSubjectDirectoryAttribute;

    public String addSubjectDirectoryAttribute() {
        addedSubjectDirectoryAttribute = new String(currentSubjectDirectoryAttribute); // I need to fetch the value from the selected component here instead...
        profiledata.addField(addedSubjectDirectoryAttribute);
        return "";// remove
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
    public List<SubjectDirectoryAttributesComponent> getSubjectDirectoryAttributeComponent() {
        List<SubjectDirectoryAttributesComponent> components = new ArrayList<SubjectDirectoryAttributesComponent>();
        List<int[]> fielddatalist = new ArrayList<int[]>();
        int numberOfSubjectDirectoryAttributeFields = profiledata.getSubjectDirAttrFieldOrderLength();
        for (int i = 0; i < numberOfSubjectDirectoryAttributeFields; i++) {
            fielddatalist.add(profiledata.getSubjectDirAttrFieldsInOrder(i));
        }
        for (int[] temp : fielddatalist) {
            boolean required = profiledata.isRequired(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            boolean modifyable = profiledata.isModifyable(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            String value = profiledata.getValue(temp[EndEntityProfile.FIELDTYPE], temp[EndEntityProfile.NUMBER]);
            components.add(new SubjectDirectoryAttributesComponent(ejbcaWebBean.getText(DnComponents.getLanguageConstantFromProfileId(temp[EndEntityProfile.FIELDTYPE])), 
                    required, modifyable, temp, value));
        }
        return components;
    }

    // MAIN CERTIFICATE DATA

    public List<SelectItem> getAvailableCertProfiles() {
        final List<SelectItem> defaultCertProfilesReturned = new ArrayList<>();
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();
        TreeMap<String, Integer> mergedMap = new TreeMap<String, Integer>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (String defaultCertProfile : mergedMap.keySet()) {
            defaultCertProfilesReturned.add(new SelectItem(defaultCertProfile, defaultCertProfile));// will need the ID, not the name, in the future
        }
        return defaultCertProfilesReturned;
    }

    //  
    public String getCurrentDefaultCertProfile() {
        int certProfile = profiledata.getDefaultCertificateProfile();
        String retValue = "";
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> mergedMap = new TreeMap<String, Integer>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (String defaultCertProfile : mergedMap.keySet()) {
            int certprofid = ((Integer) mergedMap.get(defaultCertProfile)).intValue();
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
        TreeMap<String, Integer> mergedMap = new TreeMap<String, Integer>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        int certprofid = ((Integer) mergedMap.get(defaultCertProfile)).intValue();
        profiledata.setDefaultCertificateProfile(certprofid);
    }

    // new method...
    public void setCurrentAvailableCertProfiles(Collection<String> profiles) {
        TreeMap<String, Integer> eecertificateprofilenames = ejbcaWebBean.getAuthorizedEndEntityCertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> subcacertificateprofilenames = ejbcaWebBean.getAuthorizedSubCACertificateProfileNames();//should probably b declared elsewhere
        TreeMap<String, Integer> mergedMap = new TreeMap<String, Integer>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        Collection<Integer> idCollection = new ArrayList<Integer>();
        for (String profile : profiles) {
            int certprofid = ((Integer) mergedMap.get(profile)).intValue();
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
        TreeMap<String, Integer> mergedMap = new TreeMap<String, Integer>();
        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        for (String profile : mergedMap.keySet()) {
            for (int id : availableCertProfiles) {
                if (id == ((Integer) mergedMap.get(profile)).intValue()) {
                    profilesReturned.add(profile);
                }
            }
        }
        return profilesReturned;
    }

    //
    public List<SelectItem> getAvailableCAs() {
        final List<SelectItem> defaultCAsReturned = new ArrayList<>();
        Map<Integer, String> caidtonamemap = caBean.getCAIdToNameMap();
        List<Integer> authorizedcas = ejbcaWebBean.getAuthorizedCAIds();
        Iterator<Integer> iterator = authorizedcas.iterator();
        String caidvalue;
        String caname;
        for (Integer caid : authorizedcas) {
            caid = iterator.next();
            caidvalue = caid.toString();
            caname = caidtonamemap.get(caid).toString();
            defaultCAsReturned.add(new SelectItem(caidvalue, caname));
        }
        return defaultCAsReturned;
    }

    //public void setDefaultCAs(List<SelectItem> defca) {
    //} //fake method, remove

    // new method 
    public Collection<String> getCurrentAvailableCAs() {
        Collection<String> strC = new ArrayList<String>();
        strC = profiledata.getAvailableCAsAsStrings(); //this is the IDs as string returned
        return strC;
    }

    // new method 
    public void setCurrentAvailableCAs(Collection<String> availableCAs) {
        profiledata.setAvailableCAsIDsAsStrings(availableCAs);//Tries to set String names rather than IDs probably...
    }

    // verify
    public String getCurrentDefaultCA() {
        return profiledata.getValue(EndEntityProfile.DEFAULTCA, 0);
    }

    // verify...
    public void setCurrentDefaultCA(String defaultCA) {
        Integer dcaInt = new Integer(defaultCA);
        profiledata.setDefaultCA(dcaInt.intValue());
    }

    // 
    public List<SelectItem> getAvailableTokens() {
        String[] tokenString = RAInterfaceBean.tokentexts;
        int[] tokenIds = RAInterfaceBean.tokenids;
        final List<SelectItem> availableTokensReturned = new ArrayList<>();
        String availableToken;
        String availableTokenReturned = "";//remove ?
        Integer stringElement;
        Integer availableTokenNr;
        for (stringElement = 0; stringElement < tokenString.length; stringElement++) {
            availableTokenNr = tokenIds[stringElement];
            availableToken = tokenString[stringElement.intValue()];
            availableTokenReturned = ejbcaWebBean.getText(availableToken);
            availableTokensReturned.add(new SelectItem(availableTokenNr.toString(), availableTokenReturned));
        }
        if (getHardTokenIssuers() != null) {
            Iterator<SelectItem> hardTokenIterator = getHardTokenIssuers().iterator();
            while (hardTokenIterator.hasNext()) {
                availableTokensReturned.add(hardTokenIterator.next());
            }
        }
        return availableTokensReturned;
    }

    // verify... 
    public String getCurrentDefaultToken() {
        String currentDefTokenId = profiledata.getValue(EndEntityProfile.DEFKEYSTORE, 0);
        return currentDefTokenId.toString();
    }

    //... 
    public void setCurrentDefaultToken(String defaultToken) {
        String token = defaultToken;
        profiledata.setValue(EndEntityProfile.DEFKEYSTORE, 0, token);
    }

    // new method: 
    public Collection<String> getCurrentAvailableTokens() {
        Collection<Integer> tokensAsIntegers = new ArrayList<Integer>();
        Collection<String> tokensAsStrings = new ArrayList<String>();
        tokensAsIntegers = profiledata.getAvailableTokenTypes();
        for (int tokenIntValue : tokensAsIntegers) {
            Integer tokenIntObject = new Integer(tokenIntValue);
            tokensAsStrings.add(tokenIntObject.toString());
        }
        return tokensAsStrings;
    }

    // new method:
    public void setCurrentAvailableTokens(Collection<String> tokensAsStrings) {
        String[] values = tokensAsStrings.toArray(new String[0]);
        String availableTokens = raBean.getAvailableTokenTypes(getCurrentDefaultToken(), values);
        profiledata.setValue(EndEntityProfile.AVAILKEYSTORE, 0, availableTokens);
    }

    //
    public boolean isHardTokenIssuerSystemConfigured() {
        return ejbcaWebBean.getGlobalConfiguration().getIssueHardwareTokens();
    }

    //
    public boolean isUseHardTokenIssuer() {
        return profiledata.getUse(EndEntityProfile.AVAILTOKENISSUER, 0);
    }

    //
    public void setUseHardTokenIssuer(boolean hardTokenIssuer) {
        profiledata.setUse(EndEntityProfile.AVAILTOKENISSUER, 0, hardTokenIssuer);
    }

    //
    public List<SelectItem> getHardTokenIssuers() {
        TreeMap<String, HardTokenIssuerInformation> tokenIssuerMap = ejbcaWebBean.getHardTokenIssuers();
        final List<SelectItem> hardTokenIssuersReturned = new ArrayList<>();
        Integer stringInt = new Integer(0);
        String id;
        for (Entry<String, HardTokenIssuerInformation> hardTokenIssuer : tokenIssuerMap.entrySet()) {
            stringInt = (hardTokenIssuer.getValue().getHardTokenIssuerId());
            id = stringInt.toString();
            hardTokenIssuersReturned.add(new SelectItem(id, hardTokenIssuer.getKey()));
        }
        return hardTokenIssuersReturned;
    }

    public String getCurrentDefaultHardTokenIssuer() {
        return profiledata.getValue(EndEntityProfile.DEFAULTTOKENISSUER, 0);
    }

    public void setCurrentDefaultHardTokenIssuer(String token) {
        profiledata.setValue(EndEntityProfile.DEFAULTTOKENISSUER, 0, token);
    }

    public Collection<String> getCurrentHardTokenIssuers() {
        Collection<String> currentHardTokens = new ArrayList<String>();
        String[] availableissuers = profiledata.getValue(EndEntityProfile.AVAILTOKENISSUER, 0).split(EndEntityProfile.SPLITCHAR);
        Collections.addAll(currentHardTokens, availableissuers);
        return currentHardTokens;
    }

    public void setCurrentHardTokenIssuers(Collection<String> hardTokenCollection) {
        String defaulthardtokenissuer = getCurrentDefaultHardTokenIssuer();
        String[] valueArray = hardTokenCollection.toArray(new String[0]);
        String availablehardtokenissuers = raBean.getAvailableHardTokenIssuers(defaulthardtokenissuer, valueArray);
        profiledata.setValue(EndEntityProfile.AVAILTOKENISSUER, 0, availablehardtokenissuers);
    }

    // OTHER CERTIFICATE DATA

    //
    public boolean getUseCertSerialNumber() {
        return profiledata.getCustomSerialNumberUsed();
    }

    public void setUseCertSerialNumber(boolean useCertSerialNr) {
        profiledata.setUse(EndEntityProfile.CERTSERIALNR, 0, useCertSerialNr);
    }

    //
    public boolean isUseCertValidityStartTime() {
        return profiledata.getValidityStartTimeUsed();
    }

    //
    public void setUseCertValidityStartTime(boolean useValidityStartTime) {
        profiledata.setUse(EndEntityProfile.STARTTIME, 0, useValidityStartTime);
    }

    //
    public String getValidityStartTime() {
        return profiledata.getValidityStartTime();
    }

    public void setValidityStartTime(String starttime) {
        profiledata.setValue(EndEntityProfile.STARTTIME, 0, starttime);
    }

    //
    public boolean getCertValidityStartTimeMod() {
        return profiledata.isModifyable(EndEntityProfile.STARTTIME, 0);
    }

    public void setCertValidityStartTimeMod(boolean startTimeModifyable) {
        profiledata.setModifyable(EndEntityProfile.STARTTIME, 0, startTimeModifyable);
    }

    //
    public boolean getCertValidityEndTimeMod() {
        return profiledata.isModifyable(EndEntityProfile.ENDTIME, 0);
    }

    public void setCertValidityEndTimeMod(boolean endTimeModifyable) {
        profiledata.setModifyable(EndEntityProfile.ENDTIME, 0, endTimeModifyable);
    }

    //
    public boolean getUseCertValidityEndTime() {
        return profiledata.getValidityEndTimeUsed();
    }

    //
    public void setUseCertValidityEndTime(boolean useValidityEndTime) {
        profiledata.setUse(EndEntityProfile.ENDTIME, 0, useValidityEndTime);
        ;
    }

    //
    public String getValidityEndTime() {
        return profiledata.getValidityEndTime();
    }

    public void setValidityEndTime(String endtime) {
        profiledata.setValue(EndEntityProfile.ENDTIME, 0, endtime);
    }

    //
    public boolean isCertValidityEndTimeMod() {
        return profiledata.isModifyable(EndEntityProfile.ENDTIME, 0);
    }

    //
    public String getValidityTimeExample() {
        return ejbcaWebBean.getText("OR").toLowerCase() + " " + ejbcaWebBean.getText("DAYS").toLowerCase()
                + ejbcaWebBean.getText("HOURS").toLowerCase() + ejbcaWebBean.getText("MINUTES").toLowerCase();
    }

    //
    public boolean isUseCardNumber() {
        return profiledata.getUse(EndEntityProfile.CARDNUMBER, 0);
    }

    public void setUseCardNumber(boolean useCardNumber) {
        profiledata.setUse(EndEntityProfile.CARDNUMBER, 0, useCardNumber);
    }

    //
    public boolean isCardNumberRequired() {
        return profiledata.isRequired(EndEntityProfile.CARDNUMBER, 0);
    }

    //
    public void setCardNumberRequired(boolean cardNumberRequired) {
        profiledata.setRequired(EndEntityProfile.CARDNUMBER, 0, cardNumberRequired);
    }

    //
    public boolean isUseNameConstraintsPermitted() {
        return profiledata.getUse(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0);
    }

    //
    public void setUseNameConstraintsPermitted(boolean useNameConstraintsPermitted) {
        profiledata.setUse(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0, useNameConstraintsPermitted);
    }

    //
    public boolean isUseNameConstraintsPermittedRequired() {
        return profiledata.isRequired(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0);
    }

    //
    public void setUseNameConstraintsPermittedRequired(boolean useNameConstraintsRequired) {
        profiledata.setRequired(EndEntityProfile.NAMECONSTRAINTS_PERMITTED, 0, useNameConstraintsRequired);
    }

    //
    public boolean getUseNameConstraintsExcluded() {
        return profiledata.getUse(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0);
    }

    //
    public void setUseNameConstraintsExcluded(boolean useNameConstraintsExcluded) {
        profiledata.setUse(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0, useNameConstraintsExcluded);
    }

    //
    public boolean getUseNameConstraintsExcludedRequired() {
        return profiledata.isRequired(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0);
    }

    //
    public void setUseNameConstraintsExcludedRequired(boolean useNameConstraintsExcludedRequired) {
        profiledata.setRequired(EndEntityProfile.NAMECONSTRAINTS_EXCLUDED, 0, useNameConstraintsExcludedRequired);
    }

    //
    public boolean isUseCustomCertificateExtensionData() {
        return profiledata.getUseExtensiondata();
    }

    //
    public void setUseCustomCertificateExtensionData(boolean useCustomCertificateExtensionData) {
        profiledata.setUseExtensiondata(useCustomCertificateExtensionData);
    }

    // OTHER DATA    

    //
    public boolean getUseNumberOfAllowedRequests() {
        return profiledata.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0);
    }

    public void setUseNumberOfAllowedRequests(boolean useNumberOfAllowedRequests) {
        profiledata.setUse(EndEntityProfile.ALLOWEDREQUESTS, 0, useNumberOfAllowedRequests);
    }

    //
    public List<SelectItem> getNumberOfAllowedRequests() {
        final List<SelectItem> numberOfAllowedRequestsListReturned = new ArrayList<>();
        Integer numberOfRequests;
        String numberOfRequestString;
        for (numberOfRequests = 1; numberOfRequests < 6; numberOfRequests++) {
            numberOfRequestString = numberOfRequests.toString();
            numberOfAllowedRequestsListReturned.add(new SelectItem(numberOfRequestString, numberOfRequestString));
        }
        return numberOfAllowedRequestsListReturned;
    }

    //
    public String getCurrentNumberOfAllowedRequests() {
        return profiledata.getValue(EndEntityProfile.ALLOWEDREQUESTS, 0);
    }

    // 
    public void setCurrentNumberOfAllowedRequests(String numberOfAllowedRequests) {
        profiledata.setValue(EndEntityProfile.ALLOWEDREQUESTS, 0, numberOfAllowedRequests);
    }

    // Key Recoverable

    //
    public boolean isKeyRecoverableSystemConfigured() {
        return ejbcaWebBean.getGlobalConfiguration().getEnableKeyRecovery();
    }

    //
    public boolean isUseKeyRecoverable() {
        return profiledata.getKeyRecoverableUsed();
    }

    //
    public void setUseKeyRecoverable(boolean useKeyRecoverable) {
        profiledata.setUse(EndEntityProfile.KEYRECOVERABLE, 0, useKeyRecoverable);
    }

    //
    public boolean getKeyRecoverableDefault() {
        return profiledata.getKeyRecoverableDefault();
    }

    //
    public void setKeyRecoverableDefault(boolean keyRecoverableDefault) {
        if (keyRecoverableDefault) {
            profiledata.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.TRUE);
        } else {
            profiledata.setValue(EndEntityProfile.KEYRECOVERABLE, 0, EndEntityProfile.FALSE);
        }
    }

    //
    public boolean isKeyRecoverableRequired() {
        return profiledata.getKeyRecoverableRequired();
    }

    //
    public void setKeyRecoverableRequired(boolean keyRecoverableReqired) {
        profiledata.setRequired(EndEntityProfile.KEYRECOVERABLE, 0, keyRecoverableReqired);
    }

    //
    public boolean getUseRevocationReasonAfterIssuance() {
        return profiledata.getIssuanceRevocationReasonUsed();
    }

    //
    public void setUseRevocationReasonAfterIssuance(boolean useRevocationReasonAfterIssuance) {
        profiledata.setUse(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, useRevocationReasonAfterIssuance);
    }

    //
    public String getCurrentRevocationReason() {
        return profiledata.getValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0);
    }

    //
    public void setCurrentRevocationReason(String currentRevocationReason) {
        profiledata.setValue(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, currentRevocationReason);
    }

    // verify this
    public boolean isCurrentRevocationReason(SelectItem currentRevocationReasonItem) {
        final String value = getCurrentRevocationReason();
        final String reason = currentRevocationReasonItem.getLabel();
        return reason.equals(value);
    }

    //
    public List<SelectItem> getRevocationReasons() {
        final List<SelectItem> revocationReasonsReturned = new ArrayList<>();
        String humanReadable;
        int revocationReasonDBValue;
        for (RevocationReasons revocationReason : RevocationReasons.values()) {
            humanReadable = revocationReason.getHumanReadable();
            revocationReasonDBValue = revocationReason.getDatabaseValue();
            if (revocationReasonDBValue == -1) {// Not revoked
                revocationReasonsReturned.add(0, new SelectItem(revocationReasonDBValue, ejbcaWebBean.getText("ACTIVE")));
            } else if (revocationReasonDBValue == 6) {// Certificate on hold    
                revocationReasonsReturned.add(1, new SelectItem(revocationReasonDBValue, ejbcaWebBean.getText("SUSPENDED") + ": " + humanReadable));
            } else {
                revocationReasonsReturned.add(new SelectItem(revocationReasonDBValue, ejbcaWebBean.getText("REVOKED") + ": " + humanReadable));
            }
        }
        return revocationReasonsReturned;
    }

    //
    public boolean getRevocationReasonModifyable() {
        return profiledata.getIssuanceRevocationReasonModifiable();
    }

    //
    public void setRevocationReasonModifyable(boolean revocationReasonModifyable) {
        profiledata.setModifyable(EndEntityProfile.ISSUANCEREVOCATIONREASON, 0, revocationReasonModifyable);
    }

    //
    public boolean getUseSendNotification() {
        return profiledata.getSendNotificationUsed();
    }

    //
    public void setUseSendNotification(boolean useSendNotification) {
        profiledata.setUse(EndEntityProfile.SENDNOTIFICATION, 0, useSendNotification);
    }

    private UserNotification notification;

    /*public UserNotification getNotification() {
       return notification;
    }
    
    public void setNotification(UserNotification un) {
       notification = un;
    }
    
    //This one will probably be removed, since most likely not needed when we use the UN object and it's internal methods
    public void setCurrentNotification(UserNotification notification) {
       this.notification = notification;
    }
    
    public List<UserNotification> getNotifications() {
       List<UserNotification> returnedNotifications = new ArrayList<UserNotification>();
       returnedNotifications = profiledata.getUserNotifications();
       return returnedNotifications;
    }
    
    public void setNotifications(List<UserNotification> userNotifications) {
       profiledata.setUserNotifications(userNotifications);
    }*/

    public void addNotification() {
        UserNotification newNotification = new UserNotification();
        profiledata.addUserNotification(newNotification);
    }

    // experimental
    public List<SelectItem> getAllNotificationEvents() {
        int[] statuses = ViewEndEntityHelper.statusids;
        String[] statustexts = ViewEndEntityHelper.statustexts;
        List<SelectItem> allEvents = new ArrayList<>();
        for (int i = 0; i < statuses.length; i++) {
            allEvents.add(new SelectItem(new Integer(statuses[i]).toString(), statustexts[i]));
        }
        return allEvents;
    }

    private Collection<String> currentUserNotificationEvents = new ArrayList<String>();

    //   
    public Collection<String> getCurrentNotificationEvents() {
        currentUserNotificationEvents = notification.getNotificationEventsCollection();
        return currentUserNotificationEvents;
    }

    public void setCurrentNotificationEvents(Collection<String> currentEvents) {
        notification.setNotificationEventsCollection(currentEvents);
    }

    //
    public boolean getSendNotificationDefault() {
        return profiledata.getSendNotificationDefault();
    }

    public void setSendNotificationDefault(boolean isDefault) {
        if (isDefault) {
            profiledata.setValue(EndEntityProfile.SENDNOTIFICATION, 0, EndEntityProfile.TRUE);
        } else {
            profiledata.setValue(EndEntityProfile.SENDNOTIFICATION, 0, EndEntityProfile.FALSE);
        }
    }

    public boolean getSendNotificationRequired() {
        return profiledata.getSendNotificationRequired();
    }

    public void setSendNotificationRequired(boolean isRequired) {
        profiledata.setRequired(EndEntityProfile.SENDNOTIFICATION, 0, isRequired);
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

    //
    public List<SelectItem> getPrinters() {
        String[] printerNames = raBean.listPrinters();
        final List<SelectItem> printersReturned = new ArrayList<>();
        String printerNr;
        String printer;
        String printerReturned;
        Integer stringElement;
        if (printerNames.length == 0) {
            printersReturned.add(new SelectItem("-1", ejbcaWebBean.getText("ERRORNOPRINTERFOUND")));
        } else {
            for (stringElement = 0; stringElement < printerNames.length; stringElement++) {
                printerNr = stringElement.toString();
                printer = printerNames[stringElement.intValue()];
                printerReturned = ejbcaWebBean.getText(ejbcaWebBean.getText(printer));
                printersReturned.add(new SelectItem(printerNr, printerReturned));
            }
        }
        return printersReturned;
    }

    //
    public String getCurrentPrinter() {
        return profiledata.getPrinterName();
    }

    //
    public void setCurrentPrinter(String printerName) {
        profiledata.setPrinterName(printerName);
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

    private UploadedFile uploadFile;

    public void setUploadFile(UploadedFile uploadFile) {
        this.uploadFile = uploadFile;
    }

    public UploadedFile getUploadFile() {
        return uploadFile;
    }

    public void uploadTemplate() {

    }

    public String saveProfile() throws EndEntityProfileNotFoundException, AuthorizationDeniedException {
        if (editerrors.isEmpty()) {
            String profileName = endEntityProfileSession.getEndEntityProfileName(profileId);
            raBean.changeEndEntityProfile(profileName, profiledata);
            return "profilesaved";
        } else {
            Iterator<Entry<String, String>> errorIterator = editerrors.entrySet().iterator();
            String errorMessage;
            while (errorIterator.hasNext()) {
                errorMessage = errorIterator.next().getValue();
                addNonTranslatedErrorMessage(errorMessage);//Non translated is temporary for testing
            }
        }
        return "";
        // do check if no errors
    }

    //==========================================================================================================================================================================   

    // Temporary methods, remove when it is possible
    public boolean getCheckBoxValue() {
        return false;
    }

    public void setCheckBoxValue(boolean bool) {//REMOVE?? 

    }

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
