/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.control;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.cache.AccessTreeCache;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.time.TrustedTime;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessControlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AccessControlSessionBean implements AccessControlSessionLocal, AccessControlSessionRemote {

    private static final Logger log = Logger.getLogger(AccessControlSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @EJB
    private RoleAccessSessionLocal roleAccessSession;

    // We have to depend on the internal security events logger here, since the remote depends on us
    @EJB
    private InternalSecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    /** Cache for authorization data */
    private static AccessTreeCache accessTreeCache;

    private boolean isAuthorized(final AuthenticationToken authenticationToken, final String resource, final boolean doLogging) {
        if (accessTreeCache.getAccessTree().isAuthorized(authenticationToken, resource)) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("resource", resource);
            if(doLogging) {
            	TrustedTime tt;
				try {
					tt = trustedTimeWatcherSession.getTrustedTime(false);
	                securityEventsLoggerSession.log(tt, EventTypes.ACCESS_CONTROL, EventStatus.SUCCESS, ModuleTypes.ACCESSCONTROL, ServiceTypes.CORE,
	                        authenticationToken.toString(), null, null, null, details);
				} catch (TrustedTimeProviderException e) {
					log.error("Error getting trusted time for audit log: ", e);
				}
            }
            return true;
        } else {
        	if (log.isDebugEnabled()) {
        		log.debug("Authorization failed for " + authenticationToken.toString() + " of type " + authenticationToken.getClass().getSimpleName() + " for resource " + resource);
        	}
            return false;
        }
    }
    
    @Override
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return isAuthorized(authenticationToken, resource, true);
    }
    
    @Override
    public boolean isAuthorizedNoLogging(final AuthenticationToken authenticationToken, final String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return isAuthorized(authenticationToken, resource, false);
    }

    @Override
    public void forceCacheExpire() {
        if (log.isTraceEnabled()) {
            log.trace("forceCacheExpire");
        }
        if (accessTreeCache != null) {
            accessTreeCache.forceCacheExpire();
        }
    }

    /**
     * Method used check if a reconstruction of authorization tree is needed in the authorization beans.
     * 
     * @return true if update is needed.
     */
    private boolean updateNeccessary() {
        boolean ret = false;
        // Only do the actual SQL query if we might update the configuration due to cache time anyhow
        if (accessTreeCache == null) {
            ret = true;
        } else if (accessTreeCache.needsUpdate()) {
            ret = accessTreeUpdateSession.getAccessTreeUpdateData().updateNeccessary(accessTreeCache.getAccessTreeUpdateNumber());
            // we don't want to run the above query often
        }
        if (log.isTraceEnabled()) {
            log.trace("updateNeccessary: " + false);
        }
        return ret;
    }

    /**
     * method updating authorization tree.
     */
    private void updateAuthorizationTree() {
        if (log.isTraceEnabled()) {
            log.trace(">updateAuthorizationTree");
        }
        final int authorizationtreeupdatenumber = accessTreeUpdateSession.getAccessTreeUpdateData().getAccessTreeUpdateNumber();
        if (accessTreeCache == null) {
            accessTreeCache = new AccessTreeCache();
        }

        accessTreeCache.updateAccessTree(roleAccessSession.getAllRoles(), authorizationtreeupdatenumber);
        if (log.isTraceEnabled()) {
            log.trace("<updateAuthorizationTree");
        }

    }

}
