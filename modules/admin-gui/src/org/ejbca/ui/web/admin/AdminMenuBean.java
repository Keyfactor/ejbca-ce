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
package org.ejbca.ui.web.admin;

import java.io.Serializable;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;

import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

@ViewScoped // Local variables will live as long as actions on the backed page return "" or void.
@ManagedBean
public class AdminMenuBean extends BaseManagedBean implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    private GlobalConfiguration globalConfiguration = null;
    
    private GlobalConfiguration getGlobalConfiguration() {
        if (globalConfiguration == null) {
            globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        }
        return globalConfiguration;
    }

    /*===CA FUNCTIONS===*/
    public boolean isAuthorizedToViewCA() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CAVIEW.resource());
    }
    
    public boolean isAuthorizedToViewCertificateProfile() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CERTIFICATEPROFILEVIEW.resource());
    }
    
    public boolean isAuthorizedToViewCryptotoken() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), CryptoTokenRules.VIEW.resource());
    }
    
    public boolean isAuthorizedToViewPublishers() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWPUBLISHER);
    }
    
    public boolean isAuthorizedToViewValidators() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWVALIDATOR);
    }
    
    public boolean isAuthorizedToViewCAHeader() {
        return isAuthorizedToViewCA()
                || isAuthorizedToViewCertificateProfile()
                || isAuthorizedToViewCryptotoken()
                || isAuthorizedToViewPublishers()
                || isAuthorizedToViewValidators();
    }
       
    /*===RA FUNCTIONS===*/
    
    public boolean isAuthorizedToCreateEndEntity() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_CREATEENDENTITY);
    }
    
    public boolean isAuthorizedToViewEndEntityProfiles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
    }
    
    public boolean isAuthorizedToViewEndEntity() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITY);
    }
    
    public boolean isAuthorizedToEditUserDataSources() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITUSERDATASOURCES);
    }
    
    public boolean isAuthorizedToViewRAHeader() {
        return isAuthorizedToCreateEndEntity()
                || isAuthorizedToViewEndEntityProfiles()
                || isAuthorizedToViewEndEntity()
                || isAuthorizedToEditUserDataSources();
    }
    
    /*===HARD TOKEN FUNCTIONALITY===*/
    
    public boolean isAuthorizedToEditHardTokenIssuers() {
        return getGlobalConfiguration().getIssueHardwareTokens() &&
                authorizationSession.isAuthorizedNoLogging(getAdmin(), "/hardtoken_functionality/edit_hardtoken_issuers");
    }
    
    public boolean isAuthorizedToEditHardTokenProfiles() {
        return getGlobalConfiguration().getIssueHardwareTokens() &&
                authorizationSession.isAuthorizedNoLogging(getAdmin(), "/hardtoken_functionality/edit_hardtoken_profiles");
    }
    
    public boolean isAuthorizedToViewHTHeader() {
        return getGlobalConfiguration().getIssueHardwareTokens() &&
                (isAuthorizedToEditHardTokenIssuers() || isAuthorizedToEditHardTokenProfiles());
    }
    
    /*===SUPERVISION FUNCTIONS===*/
    
    public boolean isAuthorizedToViewApprovalProfiles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.APPROVALPROFILEVIEW.resource());
    }
    
    public boolean isAuthorizedToApproveActions() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_APPROVEENDENTITY) 
                || authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_APPROVECAACTION);
    }
    
    public boolean isAuthorizedToViewLog() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AuditLogRules.VIEW.resource());
    }
    
    public boolean isAuthorizedToViewSupervisionFunctionsHeader() {
        return isAuthorizedToViewApprovalProfiles()
                || isAuthorizedToApproveActions()
                || isAuthorizedToViewLog();
    }
    
    /*===SYSTEM FUNCTIONS===*/
    
    public boolean isAuthorizedToViewRoles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.VIEWROLES.resource());
    }
    
    public boolean isAuthorizedViewInternalKeyBindings() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), InternalKeyBindingRules.VIEW.resource());
    }
    
    public boolean isAuthorizedToViewPeerConnectors() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW);
    }
    
    public boolean isAuthorizedToViewServices() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.SERVICES_VIEW);
    }
    
    public boolean isAuthorizedToViewSystemFunctionsHeader() {
        return isAuthorizedToViewRoles()
                || isAuthorizedViewInternalKeyBindings()
                || isAuthorizedToViewPeerConnectors()
                || isAuthorizedToViewServices();
    }
    
    /*===SYSTEM CONFIGURATION===*/
    
    public boolean isAuthorizedToViewSystemConfiguration() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }
    
    public boolean isAuthorizedToConfigureSystem() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource()) 
                || authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource()) 
                || authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource());
    }
    
    public boolean isUpgradeRequired() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().isPostUpgradeRequired();
    }
    
    public boolean isAuthorizedToViewSystemConfigurationHeader() {
        return isAuthorizedToViewSystemConfiguration()
                || isAuthorizedToConfigureSystem()
                || isUpgradeRequired();
    }
    
    /*===OTHER===*/
    
    public boolean isAuthorizedToEditPreferences() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.ROLE_ADMINISTRATOR);
    }
    
    public boolean isHelpEnabled() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().isHelpEnabled();
    }
    
    public String getHeadBannerUrl() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl() + getGlobalConfiguration().getHeadBanner();
    }
}
