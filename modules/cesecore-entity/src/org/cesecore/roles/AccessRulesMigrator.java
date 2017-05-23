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
package org.cesecore.roles;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.access.AccessTreeState;
import org.cesecore.authorization.rules.AccessRuleData;

/**
 * Helper class for performing access rule upgrades between the EJBCA 6.8.0+ format and before.
 * 
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public class AccessRulesMigrator {

    private static final Logger log = Logger.getLogger(AccessRulesMigrator.class);

    private final List<String> allKnownResourcesNormalized = new ArrayList<>();
    
    public AccessRulesMigrator(final Collection<String> allKnownResourcesInInstallation) {
        for (final String current : allKnownResourcesInInstallation) {
            this.allKnownResourcesNormalized.add(AccessRulesHelper.normalizeResource(current));
        }
    }
    
    public HashMap<String, Boolean> toNewAccessRules(final Collection<AccessRuleData> oldAccessRules, final String roleNameForLogging) {
        final HashMap<String, Boolean> ret = new HashMap<>();
        /*
         * 1. AccessTreeState.STATE_DECLINE is always recursive and cannot be trumped by any subrule
         * 2. AccessTreeState.STATE_ACCEPT_RECURSIVE can only be reverted by a subnode with AccessTreeState.STATE_DECLINE
         * 3. Unknown leaf nodes are declined unless a previous node had AccessTreeState.STATE_ACCEPT_RECURSIVE
         * 4. Only access rules configured in an AdminGroup are added to the AccessTree
         * 5. Application knows about all existing resource that can be configured 
         * 
         * Order of conversion below matters.
         * 
         * Generic rules:
         *  (From 1) Any /rulea/:decline          -> Remove all rules starting with /rulea/ and add /rulea/:deny to new rules
         *  (From 2) Any /ruleb/:accept+recursive -> Remove all rules starting with /ruleb/ and add /ruleb/:allow to new rules
         * 
         * Conversion of accept+nonRecursive:
         *  (From 3 and 5)
         *   Any /rulec/:accept+nonRecursive where all currently existing sub-resource are also accepted
         *     -> Add /rulec/:allow to new rules
         *   Any /rulec/:accept+nonRecursive where not all currently existing sub-resource are accepted
         *     -> Add /rulec/:allow to new rules and a /rulec/sub/:deny for each not accepted sub-resource
         * 
         * (Note that this last step changes the behavior when new sub-resources are created if all existing ones where granted at upgrade time!)
         * 
         * Complexity per role: <2*N^2+N+N*M ≃ N*M [N configured access rules in role, M total access rules in system]
         */
        final Set<AccessRuleData> oldRules = new HashSet<>(oldAccessRules);
        // If there is entries with unknown, remove them first since they provide no info
        for (final AccessRuleData accessRuleData : new ArrayList<>(oldRules)) {
            if (AccessTreeState.STATE_UNKNOWN.equals(accessRuleData.getTreeState())) {
                oldRules.remove(accessRuleData);
                if (log.isDebugEnabled()) {
                    log.debug("Ignoring STATE_UNKNOWN for resource '" + AccessRulesHelper.normalizeResource(accessRuleData.getAccessRuleName()) + "'.");
                }
            }
        }
        // Any /rulea/:decline -> Remove all rules starting with /rulea/ and add /rulea/:deny to new rules
        for (final AccessRuleData accessRuleData : new ArrayList<>(oldRules)) {
            if (AccessTreeState.STATE_DECLINE.equals(accessRuleData.getTreeState())) {
                final String resource = AccessRulesHelper.normalizeResource(accessRuleData.getAccessRuleName());
                for (final AccessRuleData current : new ArrayList<>(oldRules)) {
                    final String resourceCurrent = AccessRulesHelper.normalizeResource(current.getAccessRuleName());
                    if (resourceCurrent.startsWith(resource)) {
                        oldRules.remove(current);
                        // Remove longer resource paths that might have been added in the previous iterations of the loop
                        ret.remove(resourceCurrent);
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("Adding STATE_DENY for resource '" + resource + "'.");
                }
                ret.put(resource, Role.STATE_DENY);
            }
        }
        // Any /ruleb/:accept+recursive -> Remove all rules starting with /ruleb/ and add /ruleb/:allow to new rules
        for (final AccessRuleData accessRuleData : new ArrayList<>(oldRules)) {
            if (AccessTreeState.STATE_ACCEPT_RECURSIVE.equals(accessRuleData.getTreeState())) {
                final String resource = AccessRulesHelper.normalizeResource(accessRuleData.getAccessRuleName());
                for (final AccessRuleData current : new ArrayList<>(oldRules)) {
                    final String resourceCurrent = AccessRulesHelper.normalizeResource(current.getAccessRuleName());
                    if (resourceCurrent.startsWith(resource)) {
                        oldRules.remove(current);
                        // Remove longer resource paths that might have been added in the previous iterations of the loop
                        ret.remove(resourceCurrent);
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug("Adding STATE_ALLOW for resource '" + resource + "'.");
                }
                ret.put(resource, Role.STATE_ALLOW);
            }
        }
        // Any /rulec/:accept+nonRecursive where all currently existing sub-resource are also accepted
        //  -> Add /rulec/:allow to new rules
        // Any /rulec/:accept+nonRecursive where not all currently existing sub-resource are accepted
        //  -> Add /rulec/:allow to new rules and a /rulec/sub/:deny for each sub-resource
        final Set<String> acceptNonRecursiveRules = new HashSet<>();
        for (final AccessRuleData accessRuleData : new ArrayList<>(oldRules)) {
            if (AccessTreeState.STATE_ACCEPT.equals(accessRuleData.getTreeState())) {
                acceptNonRecursiveRules.add(AccessRulesHelper.normalizeResource(accessRuleData.getAccessRuleName()));
                oldRules.remove(accessRuleData);
            }
        }
        final List<String> acceptNonRecursiveRulesList = new ArrayList<>(acceptNonRecursiveRules);
        // Sort the list copy of the rules so log is easier to follow 
        Collections.sort(acceptNonRecursiveRulesList);
        for (final String acceptNonRecursiveRule : acceptNonRecursiveRulesList) {
            final Set<String> granted = new HashSet<>();
            final Set<String> denied = new HashSet<>();
            for (final String existingResource : allKnownResourcesNormalized) {
                // Is the known resource a sub resource to the currently processed resource
                if (existingResource.startsWith(acceptNonRecursiveRule) && !existingResource.equals(acceptNonRecursiveRule)) {
                    // Deny the sub-resource, unless 
                    // - is explicitly granted by an old accept rule
                    // - has already been granted by an accept recursive
                    if (acceptNonRecursiveRules.contains(existingResource)) {
                        granted.add(existingResource);
                    } else {
                        if (!AccessRulesHelper.hasAccessToResource(ret, existingResource)) {
                            denied.add(existingResource);
                        }
                    }
                }
            }
            if (denied.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("Adding STATE_ALLOW for resource '" + acceptNonRecursiveRule + "'.");
                }
                if (!granted.isEmpty()) {
                    log.debug("Role '" + roleNameForLogging + "' will be been granted access to all future new sub resources under '" +
                            acceptNonRecursiveRule + "', since it had access to all current sub-resources.");
                }
                ret.put(acceptNonRecursiveRule, Role.STATE_ALLOW);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Adding STATE_ALLOW for resource '" + acceptNonRecursiveRule + "'.");
                }
                ret.put(acceptNonRecursiveRule, Role.STATE_ALLOW);
                for (final String deniedSubResource : denied) {
                    if (log.isDebugEnabled()) {
                        log.debug(" and adding STATE_DENY for resource '" + deniedSubResource + "'.");
                    }
                    ret.put(deniedSubResource, Role.STATE_DENY);
                }
                log.info("Role '" + roleNameForLogging + "' will be been granted access to all future new sub resources under '" +
                        acceptNonRecursiveRule + "'. Current decline rules for sub-resources will continue to be denied.");
            }
        }
        // The unused rule '/ca_functionality/store_certificate/' was still added to roles before EJBCA 6.6.0 (clean it up now during conversion)
        ret.remove("/ca_functionality/store_certificate/");
        if (!oldRules.isEmpty()) {
            throw new IllegalStateException("Failed to convert access rules from old to new format. " + oldRules.size() + " rules remained.");
        }
        AccessRulesHelper.minimizeAccessRules(ret);
        return ret;
    }
}
