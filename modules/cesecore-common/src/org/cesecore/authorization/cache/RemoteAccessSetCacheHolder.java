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
package org.cesecore.authorization.cache;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.util.ConcurrentCache;

/**
 * Holds a ConcurrentCache which can be filled with cached AccessSets from remote systems etc. 
 * @version $Id$
 */
public final class RemoteAccessSetCacheHolder {

    private static final ConcurrentCache<AuthenticationToken,AccessSet> cache = new ConcurrentCache<>();
    
    /** Can't be instantiated */
    private RemoteAccessSetCacheHolder() { }
    
    /**
     * Returns a ConcurrentCache object that can be used for caching AccessSets from remote systems.
     * The caller is responsible for filling it with results from getAccessSetForAuthToken from the
     * remote system, but it's automatically cleared whenever local access rules change.
     */
    public static ConcurrentCache<AuthenticationToken,AccessSet> getCache() {
        return cache;
    }
    
    public static void clear() {
        cache.clear();
    }
    
    
}
