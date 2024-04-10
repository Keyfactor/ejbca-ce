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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.validators.RegexFieldValidator;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.certificate.DnComponents;

/**
*
* JSF MBean backing add end entity page.
*
*/
@Named
@ViewScoped
public class AddEndEntityMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(AddEndEntityMBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    
    private String selectedEeProfileName = "EMPTY";
    private int selectedEeProfileId = 1;
    private String defaultUsername;
    private EndEntityProfile selectedEeProfile = null;
    private int maxLoginAttempts = -1;
    private String maxLoginAttemptsStatus;
    private boolean useClearTextPasswordStorage;
    private String[] emailDomains;
    private String selectedEmailDomain;
    private String emailUserName;
    private String profileEmail;
    private String selectedSubjectDn;
    private boolean useSdnEmail;
    private boolean useAltNameEmail;
    private String selectedSubjectAltNameMultipleOptionsNoRFC822;
    
    private IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
    private IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = new IdNameHashMap<>();

    
    @PostConstruct
    public void loadConfiguration() {
        this.authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
        this.authorizedCertificateProfiles = raMasterApiProxyBean.getAuthorizedCertificateProfiles(getAdmin());
        this.selectedEeProfile = authorizedEndEntityProfiles.get(1).getValue(); // Initially EMPTY (id 1) is selected
        this.useClearTextPasswordStorage = selectedEeProfile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE);
        this.emailDomains = selectedEeProfile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
        this.profileEmail = selectedEeProfile.getValue(EndEntityProfile.EMAIL,0);
    }
    
    public boolean isOnlyOneEmailDomain() {
        if (emailDomains != null) {
            return emailDomains.length == 1;
        } else {
            return false;
        }
    }
    
    public String getEmailDomain() {
        if (emailDomains.length == 1) {
            return emailDomains[0];
        } else {
            return StringUtils.EMPTY;
        }
    }

    public String getMaxLoginAttempts() {
        return maxLoginAttempts != -1 ? String.valueOf(maxLoginAttempts) : StringUtils.EMPTY ;
    }
    
    public boolean isMaxLoginAttemptsDisabled() {
        return maxLoginAttempts == -1; 
    }
    
    public void setMaxLoginAttempts(String maxLoginAttempts) {
        this.maxLoginAttempts = Integer.parseInt(maxLoginAttempts);
    }
    
    public void actionUpdateMaxLoginAttempts() {
        try {
            this.maxLoginAttempts = Integer.parseInt(selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0));
        } catch (NumberFormatException ignored) {
        }
    }

    public String getSelectedEeProfileName() {
        return selectedEeProfileName;
    }

    public void setSelectedEeProfileName(String selectedEeProfileName) {
        this.selectedEeProfileName = selectedEeProfileName;
    }

    public List<SelectItem> getAvailableEndEntityProfiles() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(1, "EMPTY"));
        ret.addAll(authorizedEndEntityProfiles.entrySet().stream()
                .filter(item -> item.getKey() != 1)
                .map(item -> new SelectItem(String.valueOf(item.getKey()), item.getValue().getName()))
                .collect(Collectors.toList()));
        return ret;
    }
    
    public List<SelectItem> getAvailableEmailDomains() {
        final List<SelectItem> emailDomainList = new ArrayList<>();
        
        for (final String domain : emailDomains) {
            emailDomainList.add(new SelectItem(domain, domain));
        }
        
        return emailDomainList;
    }
    
    public boolean isAllowedToAddEndEntityProfile() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES);
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
                return "Must match format specified in profile. / Technical detail - the regex is" + selectedEeProfile.getUsernameDefaultValidation();
            } else {
                return getEjbcaWebBean().getText("FORMAT_ID_STR");
            }
        }
    }  
    
    public boolean isUseAutoGeneratedPassword() {
        return selectedEeProfile.useAutoGeneratedPasswd();
    }
    
    public String getPasswordFieldValue() {
        return selectedEeProfile.isPasswordPreDefined() ? getEjbcaWebBean().getText("PASSWORD_DEFINED_IN_PROFILE") : "";
    }
    
    public boolean isUseMaxFailedLoginAttempts() {
        return selectedEeProfile.getUse(EndEntityProfile.MAXFAILEDLOGINS, 0);
    }
    

    
    public boolean isMaxFailedLoginAttemptsModifiable() {
       return selectedEeProfile.isModifyable(EndEntityProfile.MAXFAILEDLOGINS,0);
    }
    
    public String actionChangeEndEntityProfile(AjaxBehaviorEvent event) {
        
        this.selectedEeProfile = authorizedEndEntityProfiles.getValue(selectedEeProfileId);
        
        try {
            this.maxLoginAttempts = Integer.parseInt(selectedEeProfile.getValue(EndEntityProfile.MAXFAILEDLOGINS, 0));
        } catch (NumberFormatException ignored) {
        }
        
        this.maxLoginAttemptsStatus = maxLoginAttempts == -1 ? "unlimited" : "specified";
        
        this.useClearTextPasswordStorage = selectedEeProfile.getValue(EndEntityProfile.CLEARTEXTPASSWORD,0).equals(EndEntityProfile.TRUE);
        this.emailDomains = selectedEeProfile.getValue(EndEntityProfile.EMAIL, 0).split(EndEntityProfile.SPLITCHAR);
        this.profileEmail = selectedEeProfile.getValue(EndEntityProfile.EMAIL,0);
        
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

    public String getSelectedEmailDomain() {
        return selectedEmailDomain;
    }

    public void setSelectedEmailDomain(String selectedEmailDomain) {
        this.selectedEmailDomain = selectedEmailDomain;
    }

    public String getProfileEmail() {
        return profileEmail;
    }

    public void setProfileEmail(String profileEmail) {
        this.profileEmail = profileEmail;
    }
    
                                         //<Label, modifiable, required>, options      
    public List<ImmutablePair<ImmutableTriple<String, String, Boolean>, Object>> getSubjectDnFieldsNameAndData() {

        final List<ImmutablePair<ImmutableTriple<String, String, Boolean>, Object>> subjectDnFieldLabelAndData = new ArrayList<>();

        int numberOfSubjectDnFields = selectedEeProfile.getSubjectDNFieldOrderLength();

        for (int i = 0; i < numberOfSubjectDnFields; i++) {
            
            
            int[] subjectDnFieldData = selectedEeProfile.getSubjectDNFieldsInOrder(i);
            
            final String fieldLabel = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(subjectDnFieldData[EndEntityProfile.FIELDTYPE]));
            final boolean fieldRequired = selectedEeProfile.isRequired(subjectDnFieldData[EndEntityProfile.FIELDTYPE], subjectDnFieldData[EndEntityProfile.NUMBER]);
            
            final boolean fieldModifiable = selectedEeProfile.isModifyable(subjectDnFieldData[EndEntityProfile.FIELDTYPE],
                    subjectDnFieldData[EndEntityProfile.NUMBER]);
            final boolean fieldEmailAddress = EndEntityProfile.isFieldOfType(subjectDnFieldData[EndEntityProfile.FIELDTYPE],
                    DnComponents.DNEMAILADDRESS);

            if (!fieldEmailAddress) {
                if (!fieldModifiable) {

                    String[] options = selectedEeProfile
                            .getValue(subjectDnFieldData[EndEntityProfile.FIELDTYPE], subjectDnFieldData[EndEntityProfile.NUMBER])
                            .split(EndEntityProfile.SPLITCHAR);

                    if (options == null) {
                        subjectDnFieldLabelAndData.add(new ImmutablePair<>(new ImmutableTriple<>(fieldLabel, "nonModifiable", fieldRequired),
                                StringUtils.EMPTY));
                    } else {
                        subjectDnFieldLabelAndData
                                .add(new ImmutablePair<>(new ImmutableTriple<>(fieldLabel, "nonModifiable", fieldRequired), options));
                    }
                } else {
                    final Map<String, Serializable> validation = selectedEeProfile.getValidation(subjectDnFieldData[EndEntityProfile.FIELDTYPE],
                            subjectDnFieldData[EndEntityProfile.NUMBER]);
                    final String regex = (validation != null ? (String) validation.get(RegexFieldValidator.class.getName()) : null);
                    
                    final String[] valueAndRegEx = {selectedEeProfile
                            .getValue(subjectDnFieldData[EndEntityProfile.FIELDTYPE], subjectDnFieldData[EndEntityProfile.NUMBER]), regex};
                    
                    subjectDnFieldLabelAndData
                            .add(new ImmutablePair<>(
                                    new ImmutableTriple<>(fieldLabel, "modifiable", fieldRequired), valueAndRegEx));
                }
            } else {
                subjectDnFieldLabelAndData.add(new ImmutablePair<>(new ImmutableTriple<>(fieldLabel, "emailAddress", fieldRequired), null));
            }
        }
        return subjectDnFieldLabelAndData;
    }
    
    // Label, Properties (modifiable, required, isRfc822name, rfc822nameString, use), <Values, Options>, regex, implemented
    public List<ImmutablePair<String, ImmutablePair<String, ImmutablePair<Object, Object>>>> getSubjectAltNameFieldsNameAndData() {

        final int numberOfSubjectAltNameFields = selectedEeProfile.getSubjectAltNameFieldOrderLength();

        final List<ImmutablePair<String, ImmutablePair<String, ImmutablePair<Object, Object>>>> subjectAltNameFieldLabelAndData = new ArrayList<>();

        for (int i = 0; i < numberOfSubjectAltNameFields; i++) {
            final int[] fieldData = selectedEeProfile.getSubjectAltNameFieldsInOrder(i);
            int fieldType = fieldData[EndEntityProfile.FIELDTYPE];

            ImmutablePair<Object, Object> fieldValuesAndOptions = null;
            String properties = null;

            // Handle RFC822NAME separately
            if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.RFC822NAME)) {
                if (selectedEeProfile.getUse(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])) {
                    properties = "isRFC822NameAndIsUse";

                    if (selectedEeProfile.isRequired(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])) {
                        properties = "isRFC822NameAndIsUseAndRequired";
                    }
                } else {

                    String rfc822NameString = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);
                    String[] rfc822NameArray = new String[2];
                    if (rfc822NameString.indexOf("@") != -1) {
                        rfc822NameArray = rfc822NameString.split("@");
                    } else {
                        rfc822NameArray[0] = "";
                        rfc822NameArray[1] = rfc822NameString;
                    }
                    final String[] rfc822NameOptions = rfc822NameString.split(EndEntityProfile.SPLITCHAR);

                    boolean modifiable = selectedEeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);

                    if (!(!modifiable && rfc822NameString.contains("@"))) {
                        properties = "isRFC822NameAndIsModifiableOrNotHaveAtSign";
                        fieldValuesAndOptions = new ImmutablePair<>(rfc822NameArray[0], null);
                    }

                    if (modifiable) {
                        properties = "isRFC822NameAndIsModifiable";
                        fieldValuesAndOptions = new ImmutablePair<>(rfc822NameArray[1], null);
                    } else {
                        properties = "isRFC822NameAndHasOptions";
                        fieldValuesAndOptions = new ImmutablePair<>(rfc822NameArray, rfc822NameOptions);
                    }
                }
            } else {

                boolean modifiable = selectedEeProfile.isModifyable(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER]);

                if (!modifiable) {
                    String[] options = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                            .split(EndEntityProfile.SPLITCHAR);

                    if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
                        if (options.length == 1) {
                            properties = "notRFC822NameAndNotModifiableAndIsUPNOneOption";
                            fieldValuesAndOptions = new ImmutablePair<>(null, options[0].trim());
                        } else {
                            properties = "notRFC822NameAndNotModifiableAndIsUPNMultipleOptions";
                            fieldValuesAndOptions = new ImmutablePair<>(null, options);
                        }
                    }
                } else {
                    if (EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.UPN)) {
                        properties = "notRFC822NameAndModifiableAndIsUPN";
                        final String fieldValue = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE],
                                fieldData[EndEntityProfile.NUMBER]);
                        fieldValuesAndOptions = new ImmutablePair<>(fieldValue, null);
                    } else {
                        if (selectedEeProfile.getCopy(fieldData[EndEntityProfile.FIELDTYPE], fieldData[EndEntityProfile.NUMBER])
                                && EndEntityProfile.isFieldOfType(fieldData[EndEntityProfile.FIELDTYPE], DnComponents.DNSNAME)) {
                            properties = "notRFC822NameAndModifiableIsCopyAndDNS";
                        } else {
                            properties = "notRFC822NameAndModifiableAndIsNotCopyAndDNS";
                        }

                        final String fieldValue = selectedEeProfile.getValue(fieldData[EndEntityProfile.FIELDTYPE],
                                fieldData[EndEntityProfile.NUMBER]);
                        final Map<String, Serializable> validation = selectedEeProfile.getValidation(fieldData[EndEntityProfile.FIELDTYPE],
                                fieldData[EndEntityProfile.NUMBER]);
                        final String regex = (validation != null ? (String) validation.get(RegexFieldValidator.class.getName()) : null);

                        fieldValuesAndOptions = new ImmutablePair<>(fieldValue, regex);
                    }
                }
            }

            if (EndEntityProfile.isFieldImplemented(fieldType)) {
                final String label = getEjbcaWebBean().getText(DnComponents.getLanguageConstantFromProfileId(fieldData[EndEntityProfile.FIELDTYPE]));
                subjectAltNameFieldLabelAndData.add(new ImmutablePair<>(label, new ImmutablePair<>(properties, fieldValuesAndOptions)));
            }
        }
        return subjectAltNameFieldLabelAndData;
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

    public boolean isUseSdnEmail() {
        return useSdnEmail;
    }

    public void setUseSdnEmail(boolean useSdnEmail) {
        this.useSdnEmail = useSdnEmail;
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
    
    
}
