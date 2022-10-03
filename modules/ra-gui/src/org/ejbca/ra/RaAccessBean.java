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

import java.io.IOException;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import org.apache.commons.collections4.MapUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.access.AuthorizationCacheReload;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.cache.RemoteAccessSetCacheHolder;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.ConcurrentCache;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Managed bean with isAuthorized method.
 *
 * @version $Id$
 */
@ManagedBean
@SessionScoped
public class RaAccessBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaAccessBean.class);

    private static final long CACHE_READ_TIMEOUT = 2000L; // milliseconds

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    @Deprecated // Breaks peer connections in the RA web. Will be removed in ECA-9938
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    private static AtomicBoolean reloadEventRegistered = new AtomicBoolean(false);

    /**
     * Called before page rendering. Checks if the current user is unauthenticated and not able to do anything.
     * If so, the user is redirected to the login page. Otherwise, the user would have to click the the "Login" link.
     *
     * This is not intended to be a security measure in any way, just a helpful redirect to the login page instead of showing a blank page.
     */
    public void preRenderView() {
        if (!skipLoginRedirect() && isUnauthenticatedWithoutAccess() && isAnyLoginProviderAvailable()) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Unauthenticated user has no access, redirecting to login page. Authentication token: " + raAuthenticationBean.getAuthenticationToken());
                }
                final ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
                ec.redirect(ec.getRequestContextPath() + "/login.xhtml");
            } catch (IOException e) {
                log.error("Unexpected error when attempting to redirect", e);
            }
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
        if (raMasterApiProxyBean.getApiVersion()>=1) {
            return raMasterApiProxyBean.isAuthorizedNoLogging(authenticationToken, resources);
        } else {
            return isAuthorizedViaAccessSet(authenticationToken, resources);
        }
    }

    /**
     * Check authorization using AccessSet which do not support deny rules.
     * @deprecated since EJBCA 6.8.0
     */
    @Deprecated
    private boolean isAuthorizedViaAccessSet(final AuthenticationToken authenticationToken, String... resources) {
        ensureCacheReloadEventRegistered();
        AccessSet myAccess;
        final ConcurrentCache<AuthenticationToken,AccessSet> cache = RemoteAccessSetCacheHolder.getCache();

        // Try to read from cache
        final ConcurrentCache<AuthenticationToken,AccessSet>.Entry entry = cache.openCacheEntry(authenticationToken, CACHE_READ_TIMEOUT);
        if (entry == null) {
            // Other thread could not fetch the AccessSet on time
            throw new IllegalStateException("Timed out waiting for access rules");
        }
        try {
            if (entry.isInCache()) {
                myAccess = entry.getValue();
            } else {
                try {
                    myAccess = raMasterApiProxyBean.getUserAccessSet(authenticationToken);
                } catch (AuthenticationFailedException e) {
                    log.info("Failed to match authentication token '" + authenticationToken + "' to a role.");
                    myAccess = new AccessSet();
                }
                entry.putValue(myAccess);
            }
        } finally {
            entry.close();
        }
        return myAccess.isAuthorized(resources);
    }

    @Deprecated
    private void ensureCacheReloadEventRegistered() {
        if (reloadEventRegistered.compareAndSet(false, true)) {
          accessTreeUpdateSession.addReloadEvent(new AuthorizationCacheReloadListener() {
                private int lastUpdate = -1;

                @Override
                public void onReload(final AuthorizationCacheReload event) {
                    if (event.getAccessTreeUpdateNumber() > lastUpdate) {
                        lastUpdate = event.getAccessTreeUpdateNumber();
                        RemoteAccessSetCacheHolder.forceEmptyCache();
                    }
                }

                @Override
                public String getListenerName() {
                    return RemoteAccessSetCacheHolder.class.getName();
                }
            });
        }
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
