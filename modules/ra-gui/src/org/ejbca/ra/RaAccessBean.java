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

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.cache.RemoteAccessSetCacheHolder;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
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

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }
    
    private boolean isAuthorized(String... resources) {
        final AuthenticationToken authenticationToken = raAuthenticationBean.getAuthenticationToken();
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
                    myAccess = new AccessSet(); // empty access set
                }
                entry.putValue(myAccess);
            }
        } finally {
            entry.close();
        }
        return myAccess.isAuthorized(resources);
    }
    
    // Methods for checking authorization to various parts of EJBCA can be defined below
    
    /** Example method */
    @Deprecated
    public boolean isAuthorizedToRootTEST() {
        return isAuthorized(StandardRules.ROLE_ROOT.resource());
    }
    
    /** correspond to menu items in menu.xhtml
     * This method shows and hides the whole enrollment menu */
    public boolean isAuthorizedToEnroll() {
        return isAuthorizedToEnrollMakeRequest() ||
                isAuthorizedToEnrollWithRequestId();
    }
    
    /** correspond to menu items in menu.xhtml
     * This method shows and hides the make request sub menu item */
    public boolean isAuthorizedToEnrollMakeRequest() {
        // Authorized to make request if user have access to at least one end entity profile
        return isAuthorized(AccessRulesConstants.ENDENTITYPROFILEPREFIX + AccessSet.WILDCARD_SOME + AccessRulesConstants.CREATE_END_ENTITY) && isAuthorized(AccessRulesConstants.REGULAR_CREATEENDENTITY);
    }
    
    /** correspond to menu items in menu.xhtml
     * This method shows and hides the use request id sub menu item */
    public boolean isAuthorizedToEnrollWithRequestId() {
        // There are no access rules available for "finalizing" requests, i.e. retrieving the certificate for your request
        // For starters we will assume that the same person who made the request is finalizing it with request ID, therefore
        // The same access rules aply as when making a request. 
        // This is a safe default until we can add access rules to allow "public" users to enroll
        return isAuthorizedToEnrollMakeRequest();
    }
    
    public boolean isAuthorizedToCas() {
        final boolean auth = isAuthorized(StandardRules.CAVIEW.resource());
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToCas: Not authorized to "+StandardRules.CAVIEW.resource());
        }
        return auth;
    }
    
    public boolean isAuthorizedToManageRequests() {
        final boolean auth = isAuthorized(AccessRulesConstants.REGULAR_APPROVEENDENTITY) || isAuthorized(AccessRulesConstants.REGULAR_APPROVECAACTION) || isAuthorized(AuditLogRules.VIEW.resource());
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToManageRequests: Not authorized to "+AccessRulesConstants.REGULAR_APPROVEENDENTITY+", "+AccessRulesConstants.REGULAR_APPROVECAACTION+" or "+AuditLogRules.VIEW.resource());
        }
        return auth;
    }
    
    public boolean isAuthorizedToApproveEndEntityRequests() {
        final boolean auth = isAuthorized(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToManageRequests: Not authorized to "+AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        }
        return auth;
    }
    
    public boolean isAuthorizedToApproveCARequests() {
        final boolean auth = isAuthorized(AccessRulesConstants.REGULAR_APPROVECAACTION);
        if (!auth && log.isDebugEnabled()) {
            log.debug(">isAuthorizedToManageRequests: Not authorized to "+AccessRulesConstants.REGULAR_APPROVECAACTION);
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
        return isAuthorized(AccessRulesConstants.REGULAR_VIEWENDENTITY); // TODO perhaps a different access rule for certs?
    }
    
    public boolean isAuthorizedToSearchEndEntities() {
        return isAuthorized(AccessRulesConstants.REGULAR_VIEWENDENTITY);
    }
    
    public boolean isAuthorizedToRoles() {
        return isAuthorized(StandardRules.VIEWROLES.resource());
    }

    public boolean isAuthorizedToRevokeCertificates() {
        return isAuthorized(AccessRulesConstants.REGULAR_REVOKEENDENTITY);
    }
}
