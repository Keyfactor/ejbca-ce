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
import org.cesecore.authentication.tokens.NestableAuthenticationToken;
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
    
    private static class AccessSetsState {
        /** Map from role primary key to list of all allowed access rules, including generated wildcard rules */
        final Map<Integer,Collection<String>> sets;
        final Collection<RoleData> roles;
        public AccessSetsState(final Map<Integer,Collection<String>> sets, final Collection<RoleData> roles) {
            this.sets = sets;
            this.roles = roles;
        }
    }
    private AccessSetsState state;
    
    public void buildAccessSets(final Collection<RoleData> roles) {
        log.trace(">buildAccessSets");
        final Map<Integer,Collection<String>> newSets = new HashMap<>();
        for (RoleData role : roles) {
            newSets.put(role.getPrimaryKey(), buildAccessSet(role));
        }
        state = new AccessSetsState(newSets, roles);
        log.trace("<buildAccessSets");
    }
    
    private Set<String> getAccessSetInternal(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final AccessSetsState state = this.state; // get object atomically
        final Set<String> set = new HashSet<>();
        for (final Integer roleId : getRoleIdsForAuthToken(authenticationToken)) {
            final Collection<String> rulesForRole = state.sets.get(roleId);
            if (rulesForRole != null) {
                set.addAll(rulesForRole);
            } else {
                log.warn("Role with primary key " + roleId + " is missing in the cache.");
            }
        }
        return set;
    }
    
    public AccessSet getAccessSetForAuthToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        if (log.isTraceEnabled()) {
            log.trace(">getAccessSetForAuthToken(" + authenticationToken + ")");
        }
        // Get the access rules for the authentication token itself
        Set<String> set = getAccessSetInternal(authenticationToken);
        
        // Get access rules for the nested authentication token
        if (authenticationToken instanceof NestableAuthenticationToken) {
            final NestableAuthenticationToken nat = (NestableAuthenticationToken) authenticationToken;
            for (final AuthenticationToken nestedToken : nat.getNestedAuthenticationTokens()) {
                final Set<String> nestedSet = getAccessSetInternal(nestedToken);
                if (log.isDebugEnabled()) {
                    log.debug("Intersecting existing " + set.size() + " access rules with " + nestedSet.size() + " rules from a nested AuthenticationToken.");
                }
                set = intersectAccessSet(set, nestedSet);
            }
        }
        
        if (log.isDebugEnabled() && set.isEmpty()) {
            log.debug("Returning empty access set for " + authenticationToken + ". All access will be denied.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAccessSetForAuthToken(" + authenticationToken + "), returning " + set.size() + " rules");
        }
        return new AccessSet(set);
    }
    
    /** Returns the resources that may be accessed from both sets. Takes recursive rules and other wildcards into account */
    private Set<String> intersectAccessSet(final Set<String> set, final Set<String> intersectWith) {
        final Set<String> result = new HashSet<>();
        
        final Set<String> ruleWiseIntersection = new HashSet<>(set);
        ruleWiseIntersection.retainAll(intersectWith);
        result.addAll(ruleWiseIntersection);
        
        // Need to take recursive rules etc. into account
        Set<String> nonMatching = new HashSet<>(intersectWith);
        nonMatching.removeAll(ruleWiseIntersection);
        AccessSet otherSet = new AccessSet(set);
        for (final String rule : nonMatching) {
            if (otherSet.isAuthorized(rule)) {
                result.add(rule);
            }
        }
        
        nonMatching = new HashSet<>(set);
        nonMatching.removeAll(ruleWiseIntersection);
        otherSet = new AccessSet(intersectWith);
        for (final String rule : nonMatching) {
            if (otherSet.isAuthorized(rule)) {
                result.add(rule);
            }
        }
        
        return result;
    }

    private Collection<Integer> getRoleIdsForAuthToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final AccessSetsState state = this.state; // get object atomically
        final Collection<Integer> roleIds = new ArrayList<>();
        for (final RoleData role : state.roles) {
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
            final String availableRule = matcher.replaceFirst("/$1/" + AccessSet.WILDCARD_SOME + "$3");
            set.add(availableRule);
            if (log.isTraceEnabled()) {
                log.trace("Added rule: " + availableRule);
            }
        }
    }
    
    private void addSubRules(final Collection<String> set, final String rulename) {
        // For now we just include the recursive rules directly, instead of trying to expand them
        final String recursiveRule = "/".equals(rulename) ? "/" + AccessSet.WILDCARD_RECURSIVE : rulename + "/" + AccessSet.WILDCARD_RECURSIVE;
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
