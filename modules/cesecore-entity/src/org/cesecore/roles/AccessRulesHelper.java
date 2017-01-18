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
import java.util.HashMap;
import java.util.Map.Entry;

/**
 * Helper methods for interactions with maps of access rules and resources.
 * 
 * @version $Id$
 */
public abstract class AccessRulesHelper {

    //private static final Logger log = Logger.getLogger(AccessRulesHelper.class);

    /** @return true if the provided map of access rules allows access to the given resource */
    public static boolean hasAccessToResource(final HashMap<String, Boolean> accessRules, final String resource) {
        if (resource==null || resource.charAt(0)!='/') {
            return false;
        }
        // Normalize from "/a/b/c" to "/a/b/c/"
        final String resourceWithTrailingSlash = resource.endsWith("/") ? resource : resource + "/";
        //log.debug("hasAccessToResource("+resource+") -> " + resourceWithTrailingSlash);
        int lastSlashIndex = resourceWithTrailingSlash.length()+1;
        while ((lastSlashIndex = resourceWithTrailingSlash.lastIndexOf('/', lastSlashIndex-1))!=-1) {
            final String subString = resourceWithTrailingSlash.substring(0, lastSlashIndex);
            Boolean state = accessRules.get(subString);
            if (state==null) {
                // Check if the non-normalized form is present
                state = accessRules.get(subString + "/");
            }
            //log.debug("hasAccessToResource("+resource+") : " + subString + " has state " + state);
            if (state!=null) {
                return state.booleanValue();
            }
        }
        return false;
    }

    /** Normalize access rules tree (make sure rules always end with a '/') */
    public static void normalizeResources(final HashMap<String, Boolean> accessRules) {
        // For each rule, check if there are higher level rules (e.g. shorter path) with the same access state
        for (final String resource : new ArrayList<>(accessRules.keySet())) {
            if (!resource.endsWith("/")) {
                final String resourceWithTrailingSlash = resource + "/";
                final Boolean value = accessRules.remove(resource);
                accessRules.put(resourceWithTrailingSlash, value);
            }
        }
    }

    /** Remove redundant rules. Assumes parameter is in normalized form. */
    public static void minimizeAccessRules(final HashMap<String, Boolean> accessRules) {
        // For each rule, check if there are higher level rules (e.g. shorter path) with the same access state
        for (final String resourceWithTrailingSlash : new ArrayList<>(accessRules.keySet())) {
            final Boolean currentState = accessRules.get(resourceWithTrailingSlash);
            if (currentState==null) {
                // Already removed from map
                continue;
            }
            //log.debug("minimizeAccessRules() " + resourceWithTrailingSlash + " currentState: " + currentState);
            int lastSlashIndex = resourceWithTrailingSlash.length()+1;
            while ((lastSlashIndex = resourceWithTrailingSlash.lastIndexOf('/', lastSlashIndex-1))!=-1) {
                if (lastSlashIndex==resourceWithTrailingSlash.length()-1) {
                    continue;
                }
                final String subString = resourceWithTrailingSlash.substring(0, lastSlashIndex+1);
                final Boolean state = accessRules.get(subString);
                //log.debug("minimizeAccessRules()  " + subString + " state: " + state);
                if (state!=null) {
                    if (state.booleanValue()==currentState.booleanValue()) {
                        // A short path already provides this rule
                        accessRules.remove(resourceWithTrailingSlash);
                    } else {
                        // The rule is needed, since it reverts a short paths state
                    }
                    break;
                }
            }
        }
        // Remove all top level deny rules (if nothing is explicitly permitted, we don't need to deny it)
        for (final String resourceWithTrailingSlash : new ArrayList<>(accessRules.keySet())) {
            final Boolean currentState = accessRules.get(resourceWithTrailingSlash);
            if (currentState!=null && !currentState.booleanValue()) {
                boolean needed = false;
                int lastSlashIndex = resourceWithTrailingSlash.length()+1;
                while ((lastSlashIndex = resourceWithTrailingSlash.lastIndexOf('/', lastSlashIndex-1))!=-1) {
                    if (lastSlashIndex==resourceWithTrailingSlash.length()-1) {
                        continue;
                    }
                    final String subString = resourceWithTrailingSlash.substring(0, lastSlashIndex+1);
                    if (accessRules.get(subString)!=null) {
                        needed = true;
                        break;
                    }
                }
                if (!needed) {
                    accessRules.remove(resourceWithTrailingSlash);
                }
            }
        }
    }

    /** @return the rules for all resources granted by either set of normalized accessRules. */
    public static HashMap<String, Boolean> mergeTotalAccess(final HashMap<String, Boolean> accessRules1, final HashMap<String, Boolean> accessRules2) {
        final HashMap<String, Boolean> accessRules = new HashMap<>();
        /*
         * Simple example of algorithm:
         * 
         * /a/   allow
         * /a/b/ deny    (remove this deny, since it is granted by other role)
         * /b/   deny    (keep since it is not granted by other role)
         * 
         * /a/   allow
         * /a/c/ deny    (remove this deny, since it is granted by other role)
         * /c/d  deny    (keep since it is not granted by other role)
         * →
         * /a/   allow
         * /b/   deny
         * /c/d  deny
         */
        // Keep allow rules from accessRules1 and deny rules from accessRules1 that are not granted by accessRules2
        for (final Entry<String, Boolean> entry : accessRules1.entrySet()) {
            if (entry.getValue().booleanValue() || !hasAccessToResource(accessRules2, entry.getKey())) {
                accessRules.put(entry.getKey(), entry.getValue());
            }
        }
        // Keep allow rules from accessRules1 and deny rules from accessRules1 that are not granted by accessRules2
        for (final Entry<String, Boolean> entry : accessRules2.entrySet()) {
            if (entry.getValue().booleanValue() || !hasAccessToResource(accessRules1, entry.getKey())) {
                accessRules.put(entry.getKey(), entry.getValue());
            }
        }
        minimizeAccessRules(accessRules);
        return accessRules;
    }
}
