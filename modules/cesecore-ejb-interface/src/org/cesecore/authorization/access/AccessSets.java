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
package org.cesecore.authorization.access;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.roles.RoleData;

/**
 * A cache of AccessSet objects, one for each role, so they can be fetched (and merged as needed) quickly.
 * Tested in {@link org.cesecore.authorization.control.AccessControlSessionBeanTest#testAccessSets()}
 * 
 * @version $Id$
 */
public final class AccessSets {

    private static final Logger log = Logger.getLogger(AccessSets.class);
    private static final Pattern idOrAllInRulename = Pattern.compile("^/(.+)/(-?[0-9]+|\\*ALL)(/|$)");
    
    /**
     * Wildcard meaning: Access is granted to some items. Used only in calls to isAuthorized to query
     * whether we have access to any of the items (and in AccessSet objects for faster access control checks).
     * <p>
     * Example: "/cryptotoken/use/*SOME", which would check if we have access to use any cryptotoken.
     */
    public static final String WILDCARD_SOME = "*SOME";
    
    /**
     * Wildcard meaning: Access is granted to all items (which must be numeric ids, currently).
     * Used in access rules only, never in calls to isAuthorized. EJBCA does not expose this feature (yet), but it's
     * tested here in CESeCore in AccessSetTest. Consider it an experimental feature.
     * <p>
     * Example: "/ca/*ALL", which would grant access to all CAs.
     */
    public static final String WILDCARD_ALL = "*ALL";
    
    /**
     * Wildcard meaning: Access is granted recursively to all subresources (but not the resource itself, for performance reasons).
     * Used internally only, never in calls to isAuthorized (AccessSets don't have anything like the requireRecursive parameter).
     * <p>
     * Example: "/*RECURSIVE" together with "/", which would grant access to everything
     */
    public static final String WILDCARD_RECURSIVE = "*RECURSIVE";
    
    /** Map from role primary key to list of all allowed access rules, including generated wildcard rules */
    private Map<Integer,Collection<String>> sets = null;
    private Collection<RoleData> roles = null;
    
    public void buildAccessSets(final Collection<RoleData> roles) {
        log.trace(">buildAccessSets");
        final Map<Integer,Collection<String>> newSets = new HashMap<>();
        for (RoleData role : roles) {
            newSets.put(role.getPrimaryKey(), buildAccessSet(role));
        }
        synchronized (this) {
            sets = newSets; // Replace the old access rules with the new ones
            this.roles = roles; // cache the available roles
        }
        log.trace("<buildAccessSets");
    }
    
    public AccessSet getAccessSetForAuthToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final Set<String> set = new HashSet<>();
        for (final Integer roleId : getRoleIdsForAuthToken(authenticationToken)) {
            final Collection<String> rulesForRole = sets.get(roleId);
            if (rulesForRole != null) {
                set.addAll(rulesForRole);
            } else {
                log.warn("Role with primary key " + roleId + " is missing in the cache.");
            }
        }
        if (log.isDebugEnabled() && set.isEmpty()) {
            log.debug("Returning empty access set for " + authenticationToken);
        }
        return new AccessSet(set);
    }
    
    private Collection<Integer> getRoleIdsForAuthToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final Collection<Integer> roleIds = new ArrayList<>();
        for (final RoleData role : roles) {
            for (final AccessUserAspect accessUser : role.getAccessUsers().values()) {
                // If aspect is of the correct token type
                if (authenticationToken.matchTokenType(accessUser.getTokenType()) && authenticationToken.matches(accessUser)) {
                    roleIds.add(role.getPrimaryKey());
                    break; // done with this role
                }
            }
        }
        if (log.isDebugEnabled() && roleIds.isEmpty()) {
            log.debug("Authentication token didn't match any roles: " + authenticationToken);
        }
        return roleIds;
    }
    
    // Proof of concept code, not optimized
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String resource) throws AuthenticationFailedException {
        if (resource.charAt(0) != '/') {
            throw new IllegalArgumentException("Resource must start with /");
        }
        
        // Get all access rules for the admin
        final AccessSet set = getAccessSetForAuthToken(authenticationToken);
        return set.isAuthorized(resource);
    }

    private Collection<String> buildAccessSet(final RoleData role) {
        if (log.isTraceEnabled()) {
            log.trace(">buildAccessSet(" + role.getRoleName() + ")");
        }
        final Collection<String> set = new HashSet<>();
        for (final AccessRuleData accessrule : role.getAccessRules().values()) {
            final AccessTreeState state = accessrule.getTreeState();
            switch (state) {
            case STATE_ACCEPT:
                addRule(set, accessrule.getAccessRuleName());
                break;
            case STATE_ACCEPT_RECURSIVE:
                addRule(set, accessrule.getAccessRuleName());
                addSubRules(set, accessrule.getAccessRuleName());
                break;
            case STATE_DECLINE:
                log.info("Decline rules are not supported by ExRA, denying all access to role '" + role.getRoleName() + "'. Resource: " + accessrule.getAccessRuleName());
                return new HashSet<>();
            case STATE_UNKNOWN:
                // Simply ignore
                break;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<buildAccessSet(" + role.getRoleName() + ")");
        }
        return set;
    }
    
    private void addRule(final Collection<String> set, final String rulename) {
        // Add the rule itself
        set.add(rulename);
        if (log.isTraceEnabled()) {
            log.trace("Added rule: " + rulename);
        }
        
        // Add wildcards
        final Matcher matcher = idOrAllInRulename.matcher(rulename);
        if (matcher.find()) {
            final String availableRule = matcher.replaceFirst("/$1/" + WILDCARD_SOME + "$3");
            set.add(availableRule);
            if (log.isTraceEnabled()) {
                log.trace("Added rule: " + availableRule);
            }
        }
    }
    
    private void addSubRules(final Collection<String> set, final String rulename) {
        // For now we just include the recursive rules directly, instead of trying to expand them
        final String recursiveRule = "/".equals(rulename) ? "/" + WILDCARD_RECURSIVE : rulename + "/" + WILDCARD_RECURSIVE;
        addRule(set, recursiveRule);
        
        // TODO this is tricky because we can't have the ejbca-specific rules in CESeCore.
        //      either we could have a "access rule registry"
        
        // XXX this is cesecore so we can't use AccessRulesConstants
        /*Map<String, Set<String>> redactedRules = getAuthorizationDataHandler()
                    .getRedactedAccessRules(AccessRulesConstants.CREATE_END_ENTITY);
        allRulesViewCache = getCategorizedRuleSet(role, redactedRules);*/
        
        // XXX this is cesecore so we can't use EjbcaConfiguration
        /*complexAccessControlSession.getAllAccessRulesRedactUnauthorizedCas(administrator,
                    globalconfiguration.getEnableEndEntityProfileLimitations(), globalconfiguration.getIssueHardwareTokens(),
                    globalconfiguration.getEnableKeyRecovery(), endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator, endentityAccessRule),
                    userdatasourcesession.getAuthorizedUserDataSourceIds(administrator, true), EjbcaConfiguration.getCustomAvailableAccessRules());*/
        
        /*private Map<String, List<AccessRuleData>> getCategorizedRuleSet(RoleData role, Map<String, Set<String>> redactedRules) {
        Map<String, List<AccessRuleData>> result = new LinkedHashMap<String, List<AccessRuleData>>();
        Map<Integer, AccessRuleData> knownRules = role.getAccessRules();
        if (redactedRules != null) {
            for (String category : redactedRules.keySet()) {
                List<AccessRuleData> subset = new ArrayList<AccessRuleData>();
                for (String rule : redactedRules.get(category)) {
                    Integer key = AccessRuleData.generatePrimaryKey(role.getRoleName(), rule);
                    if (!knownRules.containsKey(key)) {
                        // Access rule can not be found, create a new AccessRuleData that we can return
                        subset.add(new AccessRuleData(key.intValue(), rule, AccessRuleState.RULE_NOTUSED, false));
                    } else {
                        subset.add(knownRules.get(key));
                    }
                }
                result.put(category, subset);
            }
        }
        return result;*/
        
    }
    
}
