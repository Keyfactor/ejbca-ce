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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
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
        int lastSlashIndex = resourceWithTrailingSlash.length()+1;
        while ((lastSlashIndex = resourceWithTrailingSlash.lastIndexOf('/', lastSlashIndex-1))!=-1) {
            final String subString = resourceWithTrailingSlash.substring(0, lastSlashIndex);
            Boolean state = accessRules.get(subString);
            if (state==null) {
                // Check if the non-normalized form is present
                state = accessRules.get(subString + "/");
            }
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

    /** Normalize access rules (make sure rules always end with a '/') */
    public static String normalizeResource(final String resource) {
        // For each rule, check if there are higher level rules (e.g. shorter path) with the same access state
        if (!resource.endsWith("/")) {
            return resource + "/";
        }
        return resource;
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
            int lastSlashIndex = resourceWithTrailingSlash.length()+1;
            while ((lastSlashIndex = resourceWithTrailingSlash.lastIndexOf('/', lastSlashIndex-1))!=-1) {
                if (lastSlashIndex==resourceWithTrailingSlash.length()-1) {
                    continue;
                }
                final String subString = resourceWithTrailingSlash.substring(0, lastSlashIndex+1);
                final Boolean state = accessRules.get(subString);
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

    /** @return the rules for all resources granted by either sets of normalized accessRules. (The union of the sets.) */
    public static HashMap<String, Boolean> getAccessRulesUnion(final HashMap<String, Boolean> accessRules1, final HashMap<String, Boolean> accessRules2) {
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

    /** @return the rules for all resources granted by both sets of normalized accessRules. (The intersection of the sets.) */
    public static HashMap<String, Boolean> getAccessRulesIntersection(final HashMap<String, Boolean> accessRules1, final HashMap<String, Boolean> accessRules2) {
        final HashMap<String, Boolean> accessRules = new HashMap<>();
        /*
         * Simple example of algorithm:
         * 
         * /a/   allow
         * /a/b/ deny
         * /b/   deny
         * /c/d/ allow
         * 
         * /a/   allow
         * /a/c/ deny
         * /c/d/ deny
         * →
         * /a/   allow
         * /a/b/ deny
         * /a/c/ deny
         * /b/   deny
         * /c/d/ deny
         */
        // Keep deny rules from accessRules1 and allow rules from accessRules1 and that are also granted by accessRules2
        for (final Entry<String, Boolean> entry : accessRules1.entrySet()) {
            if (!entry.getValue().booleanValue() || hasAccessToResource(accessRules2, entry.getKey())) {
                accessRules.put(entry.getKey(), entry.getValue());
            }
        }
        // Keep deny rules from accessRules2 and allow rules from accessRules2 and that are also granted by accessRules1
        for (final Entry<String, Boolean> entry : accessRules2.entrySet()) {
            if (!entry.getValue().booleanValue()) {
                accessRules.put(entry.getKey(), entry.getValue());
            } else if (hasAccessToResource(accessRules1, entry.getKey())) {
                final Boolean currentValue = accessRules.get(entry.getKey());
                if (currentValue==null || currentValue.booleanValue()) {
                    // Only overwrite empty or allow rules
                    accessRules.put(entry.getKey(), entry.getValue());
                }
            }
        }
        minimizeAccessRules(accessRules);
        return accessRules;
    }

    /** Sort the provided access rules. (Useful for more readable persistence format.) */
    public static void sortAccessRules(final LinkedHashMap<String, Boolean> accessRules) {
        final List<Entry<String, Boolean>> sortEntryList = getAsListSortedByKey(accessRules);
        accessRules.clear();
        for (final Entry<String, Boolean> entry : sortEntryList) {
            accessRules.put(entry.getKey(), entry.getValue());
        }
    }

    /** @return the map sorted by keys */
    public static <T1, T2> List<Entry<T1, T2>> getAsListSortedByKey(final HashMap<T1, T2> accessRulesMap) {
        final List<Entry<T1, T2>> accessRulesList = new ArrayList<>(accessRulesMap.entrySet());
        Collections.sort(accessRulesList, new Comparator<Entry<T1, T2>>() {
            @Override
            public int compare(final Entry<T1, T2> entry1, final Entry<T1, T2> entry2) {
                return String.valueOf(entry1.getKey()).compareTo(String.valueOf(entry2.getKey()));
            }
        });
        return accessRulesList;
    }
}
