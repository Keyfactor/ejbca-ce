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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
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
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.NestableAuthenticationToken;
import org.cesecore.authorization.cache.AccessTreeCache;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.cache.RemoteAccessSetCacheHolder;
import org.cesecore.internal.InternalResources;
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
@Deprecated
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessControlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AccessControlSessionBean implements AccessControlSessionLocal, AccessControlSessionRemote {

    private static final Logger log = Logger.getLogger(AccessControlSessionBean.class);

    /* Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @EJB
    private RoleAccessSessionLocal roleAccessSession;

    // We have to depend on the internal security events logger here, since the remote depends on us
    @EJB
    private InternalSecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    /** 
     * Cache for authorization data 
     * 
     * This class member knowingly breaks the EJB standard which forbids static volatile class members. The
     * spirit of this rule is to prohibit implementations from using mutexes in their SSBs, thus negating the
     * EJB bean pool. It doesn't take into account the need to cache data in a shared singleton, thus we have 
     * to knowingly break the standard, but not its spirit. 
     * 
     */
    private static volatile AccessTreeCache accessTreeCache;

    private boolean isAuthorized(final AuthenticationToken authenticationToken, final boolean doLogging, final boolean requireRecursive, final String... resources) {
        if (authenticationToken!=null && authenticationToken instanceof NestableAuthenticationToken) {
            final List<NestableAuthenticationToken> nestedAuthenticatonTokens = ((NestableAuthenticationToken)authenticationToken).getNestedAuthenticationTokens();
            // Start with the closest AuthenticatonToken (that this server has performed authentication for and hence the authentication can be trusted more)
            Collections.reverse(nestedAuthenticatonTokens);
            for (final NestableAuthenticationToken nestableAuthenticationToken : nestedAuthenticatonTokens) {
                if (!isAuthorizedSingleToken(nestableAuthenticationToken, doLogging, requireRecursive, resources)) {
                    return false;
                }
            }
        }
        // Finally, check the most outer AuthenticationToken
        return isAuthorizedSingleToken(authenticationToken, doLogging, requireRecursive, resources);
    }

    private boolean isAuthorizedSingleToken(final AuthenticationToken authenticationToken, final boolean doLogging, final boolean requireRecursive, final String... resources) {
        try {
            Map<String, Object> details = null;
            if (doLogging) {
                details = new LinkedHashMap<>();
            }
            for (int i=0; i<resources.length; i++) {
                final String resource = resources[i];
                if (accessTreeCache.getAccessTree().isAuthorized(authenticationToken, resource, requireRecursive)) {
                    if (doLogging) {
                        details.put("resource"+i, resource);
                    }
                } else {
                    // At least log failed authorization attempts as INFO, even though CC does not require any sec audit
                    // If we are checking authorization without logging, for example to see if an admin menu should be available, only log at debug level.
                    // Note: same message below, but if debug logging is not enabled we don't want to construct the string at all (to save time and objects) for debug logging, therefore code copied.
                    if (doLogging) {
                        log.info("Authorization failed for " + authenticationToken.toString() + " of type " + authenticationToken.getClass().getSimpleName() + " for resource " + resource);                        
                    } else if (log.isDebugEnabled()) {
                        log.debug("Authorization failed for " + authenticationToken.toString() + " of type " + authenticationToken.getClass().getSimpleName() + " for resource " + resource);                        
                    }
                    // We failed one of the checks, so there is no point in continuing..
                    // If we failed an authorization check, there is no need to log successful ones before this point since
                    // the requester has not yet been (and never will be) notified of the successful outcomes.
                    return false;
                }
            }
            if (doLogging) {
                TrustedTime tt = null;
                try {
                    tt = trustedTimeWatcherSession.getTrustedTime(false);
                } catch (TrustedTimeProviderException e) {
                    log.error("Error getting trusted time for audit log: ", e);
                }
                securityEventsLoggerSession.log(tt, EventTypes.ACCESS_CONTROL, EventStatus.SUCCESS, ModuleTypes.ACCESSCONTROL,
                        ServiceTypes.CORE, authenticationToken.toString(), null, null, null, details);
            }
            return true;
        } catch (AuthenticationFailedException e) {
            final Map<String, Object> details = new LinkedHashMap<>();
            String msg = intres.getLocalizedMessage("authentication.failed", e.getMessage());
            details.put("msg", msg);
            try {
                securityEventsLoggerSession.log(trustedTimeWatcherSession.getTrustedTime(false), EventTypes.AUTHENTICATION, EventStatus.FAILURE,
                        ModuleTypes.AUTHENTICATION, ServiceTypes.CORE, authenticationToken.toString(), null, null, null, details);
            } catch (TrustedTimeProviderException f) {
                log.error("Error getting trusted time for audit log: ", e);
            }
        }
        return false;
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorized(final AuthenticationToken authenticationToken, boolean requireRecursive, final String... resources) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return isAuthorized(authenticationToken, true, requireRecursive, resources);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String... resources) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return isAuthorized(authenticationToken, true, false, resources);
    }
    
    @Override
    public boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, boolean requireRecursive, String... resources) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return isAuthorized(authenticationToken, false, requireRecursive, resources);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorizedNoLogging(final AuthenticationToken authenticationToken, final String... resources) {
      return isAuthorizedNoLogging(authenticationToken, false, resources);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void forceCacheExpire() {
        if (log.isTraceEnabled()) {
            log.trace("forceCacheExpire");
        }
        if (accessTreeCache != null) {
            accessTreeCache.forceCacheExpire();
        }
        // Clear the local RA Access Set Cache
        RemoteAccessSetCacheHolder.forceEmptyCache();
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
            // Only one thread needs to check if there are database changes from other nodes and
            // if there isn't any change, we don't need to check this for another "cachetime"
            accessTreeCache.setLastUpdateToNow();
            ret = accessTreeUpdateSession.getAccessTreeUpdateNumber() > accessTreeCache.getAccessTreeUpdateNumber();
        }
        if (log.isTraceEnabled()) {
            log.trace("updateNeccessary: " + ret);
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
        final int authorizationtreeupdatenumber = accessTreeUpdateSession.getAccessTreeUpdateNumber();
        if (accessTreeCache == null) {
            accessTreeCache = new AccessTreeCache();
        }
        accessTreeCache.updateAccessTree(roleAccessSession.getAllRoles(), authorizationtreeupdatenumber);
        if (log.isTraceEnabled()) {
            log.trace("<updateAuthorizationTree");
        }
    }
}
