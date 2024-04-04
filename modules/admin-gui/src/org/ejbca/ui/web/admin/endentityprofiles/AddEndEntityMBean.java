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
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.enterprise.context.SessionScoped;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.admin.BaseManagedBean;

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
    private String profileEmail;
    
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
    
    public boolean isOnlyOneDomainEmail() {
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
    
}
