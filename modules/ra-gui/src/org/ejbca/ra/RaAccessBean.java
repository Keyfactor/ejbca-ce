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
import javax.faces.bean.RequestScoped;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.cache.RemoteAccessSetCacheHolder;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.util.ConcurrentCache;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Managed bean with isAuthorized method. 
 * 
 * @version $Id$
 */
@ManagedBean
@RequestScoped
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
}
