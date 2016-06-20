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

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

/**
 * Represents all access rules that a given AuthenticationToken is allowed to access.
 * 
 * @version $Id$
 */
public final class AccessSet implements Serializable {
    
    private static final Logger log = Logger.getLogger(AccessSet.class);
    private static final long serialVersionUID = -6522714939328731306L;
    
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
    
    private static final Pattern idInRulename = Pattern.compile("^/(.+)/(-?[0-9]+)(/|$)");
    private static final String WILDCARD_REPLACEMENT = "/$1/" + WILDCARD_ALL + "$3";
    
    private final Collection<String> set;
    
    /** No-args constructor is used for deserialization only */
    public AccessSet() {
        this.set = new HashSet<>();
    }
    
    /** Creates an AccessSet with access to the given access rules collection as built from AccessSet. */
    public AccessSet(final Collection<String> set) {
        this.set = new HashSet<>(set);
    }

    /** Creates an access set merged from two access sets. */
    public AccessSet(final AccessSet a, final AccessSet b) {
        set = new HashSet<>(a.set.size() + b.set.size());
        set.addAll(a.set);
        set.addAll(b.set);
    }

    public boolean isAuthorized(final String... resources) {
        // Note that "*SOME" rules are added when the rules for the AccessSet are built, and don't need to be handled here
        NEXT_RESOURCE: for (final String resource : resources) {
            if (resource.charAt(0) != '/') {
                throw new IllegalArgumentException("Resource must start with /");
            } else if (resource.length() != 1 && resource.charAt(resource.length() - 1) == '/') {
                throw new IllegalArgumentException("Resource should not end with /");
            }
            
            // Check for exact rule
            if (set.contains(resource)) {
                continue NEXT_RESOURCE; // OK. Check next resource
            }
            
            // Check for recursive rules
            int depth = 0;
            String parentResource = resource;
            for (; depth < 100; depth++) { // never split more than 100 times
                int slash = parentResource.lastIndexOf('/');
                if (slash == -1) {
                    break;
                }
                parentResource = parentResource.substring(0, slash);
                if (log.isTraceEnabled()) {
                    log.trace("Checking for '"+ parentResource + "/" + WILDCARD_RECURSIVE + "'");
                }
                if (set.contains(parentResource + "/" + WILDCARD_RECURSIVE)) {
                    continue NEXT_RESOURCE; // OK. Check next resource
                }
            }
            if (depth == 100 && log.isDebugEnabled()) {
                // Recursive rules are always accept rules, so it's safe to ignore some of them and continue
                log.debug("Resource had more than 100 components, only the first 100 were checked for recursive accept access: " + resource);
            }
            
            // If it contains an id, check for *ALL rules also
            final Matcher matcher = idInRulename.matcher(resource);
            if (matcher.find()) {
                final String withWildcardAll = matcher.replaceFirst(WILDCARD_REPLACEMENT);
                if (!isAuthorized(withWildcardAll)) {
                    if (log.isTraceEnabled()) {
                        log.trace("No access rule for " + resource + ". Denying access. Number of allowed resources=" + set.size());
                    }
                    return false;
                }
            } else {
                if (log.isTraceEnabled()) {
                    log.trace("No access rule for " + resource + ". Denying access. Number of allowed resources=" + set.size());
                }
                return false;
            }
        }
        return true; // all resources match
    }
    
    /** @deprecated Used in tests only */
    @Deprecated
    public void dumpRules() {
        for (final String resource : set) {
            log.debug("Resource: " + resource);
        }
    }
    
    @Override
    public boolean equals(final Object object) {
        if (object instanceof AccessSet) {
            AccessSet accessSet = (AccessSet) object;
            return set.containsAll(accessSet.set) && accessSet.set.containsAll(set);
        }
        return false;
    }
}
