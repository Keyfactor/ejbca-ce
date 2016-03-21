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
    
    private static final Pattern idInRulename = Pattern.compile("^/(.+)/(-?[0-9]+)(/|$)");
    private static final String WILDCARD_REPLACEMENT = "/$1/" + AccessSets.WILDCARD_ALL + "$3";
    
    private final Collection<String> set;
    
    /** No-args constructor is used for deserialization only */
    public AccessSet() {
        this.set = new HashSet<>();
    }
    
    /** Creates an AccessSet with access to the given access rules collection as built from AccessSet. */
    public AccessSet(final Collection<String> set) {
        this.set = new HashSet<>(set);
    }

    public boolean isAuthorized(final String... resources) {
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
            String parentResource = resource;
            while (true) {
                int slash = parentResource.lastIndexOf('/');
                if (slash == -1) {
                    break;
                }
                parentResource = parentResource.substring(0, slash);
                if (log.isTraceEnabled()) {
                    log.trace("Checking for '"+ parentResource + "/" + AccessSets.WILDCARD_RECURSIVE + "'");
                }
                if (set.contains(parentResource + "/" + AccessSets.WILDCARD_RECURSIVE)) {
                    continue NEXT_RESOURCE; // OK. Check next resource
                }
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
    
}
