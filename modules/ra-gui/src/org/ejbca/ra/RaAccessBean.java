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

import org.apache.commons.collections4.MapUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.util.HttpTools;

import jakarta.ejb.EJB;
import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;
import jakarta.inject.Named;

/**
 * Managed bean with isAuthorized method.
 *
 */
@Named
@SessionScoped
public class RaAccessBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaAccessBean.class);


    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    @Deprecated // Breaks peer connections in the RA web. Will be removed in ECA-9938
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    /**
     * Called before page rendering. Checks if the current user is unauthenticated and not able to do anything.
     * If so, the user is redirected to the login page. Otherwise, the user would have to click the the "Login" link.
     *
     * This is not intended to be a security measure in any way, just a helpful redirect to the login page instead of showing a blank page.
     */
    public void preRenderView() {
        if (!skipLoginRedirect() && isUnauthenticatedWithoutAccess() && isAnyLoginProviderAvailable()) {
            if (log.isDebugEnabled()) {
                log.debug("Unauthenticated user has no access, redirecting to login page. Authentication token: " + raAuthenticationBean.getAuthenticationToken());
            }
            HttpTools.sendRedirect(FacesContext.getCurrentInstance(), "/login.xhtml");
        }
    }

    private boolean skipLoginRedirect() {
        return FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().containsKey("skipLoginRedirect");
    }

    private boolean isAnyLoginProviderAvailable() {
        final OAuthConfiguration  oauthConfiguration = raMasterApiProxyBean.getGlobalConfiguration(OAuthConfiguration.class);
        // Older versions than 7.5.0 will return null here
        return oauthConfiguration != null && MapUtils.isNotEmpty(oauthConfiguration.getOauthKeys());
    }

    public boolean isAuthorizedToAnything() {
        return isAuthorizedToEnroll() || isAuthorizedToSearch() ||isAuthorizedToManageRequests() ||
                isAuthorizedToRoles() || isAuthorizedToCas();
    }

    /**
     * Returns true if the user is unauthenticated, and does not have access to anything.
     * In that case, the only meaningful action is to log in.
     */
    public boolean isUnauthenticatedWithoutAccess() {
        return raAuthenticationBean.isPublicUser() && !isAuthorizedToAnything();
    }

    private boolean isAuthorized(String... resources) {
        final AuthenticationToken authenticationToken = raAuthenticationBean.getAuthenticationToken();
        return raMasterApiProxyBean.isAuthorizedNoLogging(authenticationToken, resources);

    }


   

    // Methods for checking authorization to various parts of EJBCA can be defined below

    /** Example method */
    @Deprecated
    public boolean isAuthorizedToRootTEST() {
        return isAuthorized(StandardRules.ROLE_ROOT.resource());
    }

    /** correspond to menu items in menu.xhtml
     * This method shows and hides the whole or part of enrollment menu depending on access rules*/
    public boolean isAuthorizedToEnroll() {
        return isAuthorizedToEnrollMakeRequest() ||
                isAuthorizedToEnrollUsingUsername() ||
                isAuthorizedToEnrollUsingApprovalRequestId();
    }

    /** correspond to menu items in menu.xhtml
     * This method shows and hides the make request sub menu item */
    public boolean isAuthorizedToEnrollMakeRequest() {
        /*
         * Only check if this admin has been configured to create end entities to display the menu.
         * In order to actually make a request, the admin has to have access to
         *  AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.CREATE_END_ENTITY
         * and the CAs available via this profile.
         */
        return isAuthorized(AccessRulesConstants.REGULAR_CREATEENDENTITY);
    }

    public boolean isAuthorizedToEnrollUsingUsername() {
        return isAuthorized(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRulesConstants.REGULAR_USEUSERNAME);
    }

    public boolean isAuthorizedToEnrollUsingApprovalRequestId() {
        return isAuthorized(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRulesConstants.REGULAR_USEAPPROVALREQUESTID);
    }

    public boolean isAuthorizedToCas() {
        final boolean auth = isAuthorized(StandardRules.CAVIEW.resource());
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToCas: Not authorized to "+StandardRules.CAVIEW.resource());
        }
        return auth;
    }
     
    public boolean isAuthorizedToManageRequests() {
        final boolean auth = isAuthorized(AccessRulesConstants.REGULAR_APPROVEENDENTITY) || isAuthorized(AccessRulesConstants.REGULAR_APPROVECAACTION) 
                || isAuthorized(AccessRulesConstants.REGULAR_VIEWAPPROVALS) || isAuthorized(AuditLogRules.VIEW.resource());
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToManageRequests: Not authorized to "+AccessRulesConstants.REGULAR_APPROVEENDENTITY+", "+AccessRulesConstants.REGULAR_APPROVECAACTION+", "
                +AccessRulesConstants.REGULAR_VIEWAPPROVALS+" or "+AuditLogRules.VIEW.resource()); 
        }
        return auth;
    }

    public boolean isAuthorizedToApproveEndEntityRequests() {
        final boolean auth = isAuthorized(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToApproveEndEntityRequests: Not authorized to "+AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        }
        return auth;
    }

    public boolean isAuthorizedToApproveCARequests() {
        final boolean auth = isAuthorized(AccessRulesConstants.REGULAR_APPROVECAACTION);
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToApproveCARequests: Not authorized to "+AccessRulesConstants.REGULAR_APPROVECAACTION);
        }
        return auth;
    }

    public boolean isAuthorizedToEditEndEntities() {
        return isAuthorized(AccessRulesConstants.REGULAR_EDITENDENTITY);
    }

    public boolean isAuthorizedToSearch() {
        return isAuthorizedToSearchCerts() ||
                isAuthorizedToSearchEndEntities();
    }

    public boolean isAuthorizedToSearchCerts() {
        return isAuthorized(AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
    }

    public boolean isAuthorizedToSearchEndEntities() {
        return isAuthorized(AccessRulesConstants.REGULAR_VIEWENDENTITY);
    }

    public boolean isAuthorizedToRoles() {
        return isAuthorizedToRoleRules() || isAuthorizedToRoleMembers();
    }

    public boolean isAuthorizedToEditRoleRules() {
        return isAuthorized(StandardRules.EDITROLES.resource());
    }

    public boolean isAuthorizedToRoleRules() {
        return isAuthorized(StandardRules.VIEWROLES.resource());
    }

    public boolean isAuthorizedToRoleMembers() {
        return isAuthorized(StandardRules.VIEWROLES.resource());
    }

    public boolean isAuthorizedToEditRoleMembers() {
        return isAuthorized(StandardRules.EDITROLES.resource());
    }

    public boolean isAuthorizedToRevokeCertificates() {
        return isAuthorized(AccessRulesConstants.REGULAR_REVOKEENDENTITY);
    }

    public boolean isAuthorizedToRenewClientCertificate() {
        // TODO add separate access rules for this?
        return isAuthorized(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRulesConstants.REGULAR_EDITENDENTITY);
    }

    /**
     * Determine if the RA master API is functional. Note that this method will
     * return true if there is a signing CA available locally on this RA.
     * @return true if there is at least one CA serving this RA
     */
    public boolean isBackendAvailable() {
        final boolean isBackendAvailable = raMasterApiProxyBean.isBackendAvailable();
        if (!isBackendAvailable) {
            log.warn("Unable to serve RA requests since there is no connection to the upstream CA or lack of authorization of this RA node.");
        }
        return isBackendAvailable;
    }

    public boolean hasCaAccess() {
        return isAuthorized(StandardRules.CAACCESS.resource());
    }

    public boolean hasEndEntityProfileAccess() {
        return isAuthorized(AccessRulesConstants.ENDENTITYPROFILEPREFIX);
    }

    public boolean isRunningEnterprise() {
        try {
            Class.forName("org.ejbca.ra.enterprise.RaWebEnterpriseClass");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public String getEditionFolder() {
        return isRunningEnterprise() ? "EE" : "CE";
    }
}
