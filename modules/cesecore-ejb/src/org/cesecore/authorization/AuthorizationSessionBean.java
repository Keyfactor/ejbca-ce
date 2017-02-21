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
package org.cesecore.authorization;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.NestableAuthenticationToken;
import org.cesecore.authorization.AuthorizationCache.AuthorizationCacheCallback;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.cache.RemoteAccessSetCacheHolder;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.time.TrustedTime;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * 
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AuthorizationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AuthorizationSessionBean implements AuthorizationSessionLocal, AuthorizationSessionRemote {

    private static final Logger log = Logger.getLogger(AuthorizationSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private InternalSecurityEventsLoggerSessionLocal internalSecurityEventsLoggerSession;
    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    @Resource
    private SessionContext sessionContext;
    private TimerService timerService; // When the sessionContext is injected, the timerService should be looked up.
    private AuthorizationSessionLocal authorizationSession;

    @PostConstruct
    public void postConstruct() {
        timerService = sessionContext.getTimerService();
        authorizationSession = sessionContext.getBusinessObject(AuthorizationSessionLocal.class);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void scheduleBackgroundRefresh() {
        for (final Timer timer : timerService.getTimers()) {
            timer.cancel();
        }
        timerService.createSingleActionTimer(0, new TimerConfig("AuthorizationSessionTimer", false));
    }

    @Override
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeOut(final Timer timer) {
        authorizationSession.refreshAuthorizationCache();
        timerService.createSingleActionTimer(CesecoreConfiguration.getCacheAuthorizationTime(), new TimerConfig("AuthorizationSessionTimer", false));
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String... resources) {
        return isAuthorized(authenticationToken, true, resources);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorizedNoLogging(final AuthenticationToken authenticationToken, final String... resources) {
        return isAuthorized(authenticationToken, false, resources);
    }

    private boolean isAuthorized(final AuthenticationToken authenticationToken, final boolean doLogging, final String... resources) {
        try {
            final HashMap<String, Boolean> accessRules = getAccessAvailableToAuthenticationToken(authenticationToken);
            final Map<String, Object> details = doLogging ? new LinkedHashMap<String, Object>() : null;
            for (int i=0; i<resources.length; i++) {
                final String resource = resources[i];
                final boolean authorizedToResource = AccessRulesHelper.hasAccessToResource(accessRules, resource);
                if (authorizedToResource) {
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
                internalSecurityEventsLoggerSession.log(getTrustedTime(), EventTypes.ACCESS_CONTROL, EventStatus.SUCCESS, ModuleTypes.ACCESSCONTROL,
                        ServiceTypes.CORE, authenticationToken.toString(), null, null, null, details);
            }
            return true;
        } catch (AuthenticationFailedException e) {
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", InternalResources.getInstance().getLocalizedMessage("authentication.failed", e.getMessage()));
            internalSecurityEventsLoggerSession.log(getTrustedTime(), EventTypes.AUTHENTICATION, EventStatus.FAILURE, ModuleTypes.AUTHENTICATION,
                    ServiceTypes.CORE, authenticationToken.toString(), null, null, null, details);
        }
        return false;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void forceCacheExpire() {
        if (log.isTraceEnabled()) {
            log.trace("forceCacheExpire");
        }
        AuthorizationCache.INSTANCE.clear(accessTreeUpdateSession.getAccessTreeUpdateNumber());
        // Clear the local RA Access Set Cache
        RemoteAccessSetCacheHolder.forceEmptyCache();
        authorizationSession.scheduleBackgroundRefresh();
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void refreshAuthorizationCache() {
        if (log.isTraceEnabled()) {
            log.trace("updateCache");
        }
        AuthorizationCache.INSTANCE.refresh(authorizationCacheCallback);
    }
    
    /** @return the access rules available to the AuthenticationToken and its nested tokens, taking each such tokens role membership into account */
    private HashMap<String, Boolean> getAccessAvailableToAuthenticationToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        return AuthorizationCache.INSTANCE.get(authenticationToken, authorizationCacheCallback);
    }
    
    /** Callback for loading cache misses */
    private AuthorizationCacheCallback authorizationCacheCallback = new AuthorizationCacheCallback() {
        @Override
        public HashMap<String, Boolean> loadAccessRules(final AuthenticationToken authenticationToken) {
            HashMap<String, Boolean> accessRules = getAccessAvailableToSingleToken(authenticationToken);
            if (authenticationToken instanceof NestableAuthenticationToken) {
                final List<NestableAuthenticationToken> nestedAuthenticatonTokens = ((NestableAuthenticationToken)authenticationToken).getNestedAuthenticationTokens();
                for (final NestableAuthenticationToken nestableAuthenticationToken : nestedAuthenticatonTokens) {
                    final HashMap<String, Boolean> accessRulesForNestedToken = getAccessAvailableToSingleToken(nestableAuthenticationToken);
                    accessRules = AccessRulesHelper.getAccessRulesIntersection(accessRules, accessRulesForNestedToken);
                }
            }
            if (log.isDebugEnabled()) {
                debugLogAccessRules(authenticationToken, accessRules);
            }
            return accessRules;
        }

        @Override
        public int getUpdateNumber() {
            return accessTreeUpdateSession.getAccessTreeUpdateNumber();
        }

        @Override
        public long getKeepUnusedEntriesFor() {
            // Setting this to the same as the background cache refresh interval means that any token that has not been used will be purged
            return CesecoreConfiguration.getCacheAuthorizationTime();
        }
    };

    private void debugLogAccessRules(final AuthenticationToken authenticationToken, final HashMap<String, Boolean> accessRules) {
        final StringBuilder sb = new StringBuilder(authenticationToken.toString()).append(" has the following access rules:\n");
        for (final Entry<String,Boolean> entry : accessRules.entrySet()) {
            if (entry.getValue().booleanValue()) {
                sb.append(" allow ");
            } else {
                sb.append(" deny  ");
            }
            sb.append(entry.getKey()).append('\n');
        }
        log.debug(sb);
    }

    /** @return the union of access rules available to the AuthenticationToken if it matches several roles (ignoring any nested tokens) */
    @SuppressWarnings("deprecation")
    private HashMap<String, Boolean> getAccessAvailableToSingleToken(final AuthenticationToken authenticationToken) {
        HashMap<String, Boolean> accessRules = new HashMap<>();
        if (authenticationToken!=null) {
            if (authenticationToken.getMetaData().isSuperToken()) {
                try {
                    if (authenticationToken.matches(null)) {
                        // Special handing of the AlwaysAllowAuthenticationToken to grant full access
                        accessRules.put("/", Boolean.TRUE);
                    }
                } catch (AuthenticationFailedException e) {
                    log.debug(e.getMessage(), e);
                }
            } else {
                if (accessTreeUpdateSession.isNewAuthorizationPatternMarkerPresent()) {
                    // This is the new 6.8.0+ behavior (combine access of matched rules)
                    for (final int matchingRoleId : roleMemberSession.getRoleIdsMatchingAuthenticationToken(authenticationToken)) {
                        accessRules = AccessRulesHelper.getAccessRulesUnion(accessRules, roleDataSession.getRole(matchingRoleId).getAccessRules());
                    }
                } else {
                    // This is the legacy behavior (use priority matching). Remove this once we no longer need to support upgrades to 6.8.0.
                    // Greater tokenMatchKey number has higher priority. When equal, deny trumps accept
                    final Map<Integer, Integer> roleIdToTokenMatchKeyMap = roleMemberSession.getRoleIdsAndTokenMatchKeysMatchingAuthenticationToken(authenticationToken);
                    final Map<Integer, Integer> keepMap = new HashMap<>();
                    // 1. Find highest tokenMatchKey number and keep these entries
                    int highest = 0;
                    for (final Entry<Integer,Integer> entry : roleIdToTokenMatchKeyMap.entrySet()) {
                        final int current = entry.getValue();
                        if (highest<current) {
                            keepMap.clear();
                            highest = current;
                        }
                        if (highest == current) {
                            keepMap.put(entry.getKey(), entry.getValue());
                        }
                    }
                    // 2. Get the intersection of rights for all matching roles
                    if (!keepMap.isEmpty()) {
                        accessRules.put("/", Boolean.TRUE);
                        for (final int matchingRoleId : keepMap.keySet()) {
                            accessRules = AccessRulesHelper.getAccessRulesIntersection(accessRules, roleDataSession.getRole(matchingRoleId).getAccessRules());
                        }
                    }
                }
            }
        }
        return accessRules;
    }

    /** @return the trusted time requires for audit logging */
    private TrustedTime getTrustedTime() throws AuditRecordStorageException {
        try {
            return trustedTimeWatcherSession.getTrustedTime(false);
        } catch (TrustedTimeProviderException e) {
            log.error(e.getMessage(), e);
            throw new AuditRecordStorageException(e.getMessage(), e);
        }
    }
}
