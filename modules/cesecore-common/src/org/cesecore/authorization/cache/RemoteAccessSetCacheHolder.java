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

import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.util.ConcurrentCache;

/**
 * Holds a ConcurrentCache which can be filled with cached AccessSets from remote systems etc. 
 * @version $Id$
 */
public final class RemoteAccessSetCacheHolder {
    
    private static final Logger log = Logger.getLogger(RemoteAccessSetCacheHolder.class);

    // These fields are also modified by the test RemoteAccessSetCacheHolderTest
    private static volatile int lastUpdate = -1;
    private static volatile boolean regularUpdateInProgress = false; // not clear caches etc.
    private static final Object checkClearLock = new Object();
    private static ConcurrentCache<AuthenticationToken,AccessSet> cache = new ConcurrentCache<>();
    
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
    
    /**
     * Starts a cache reload. The caller is responsible for actually building the cache data after
     * calling this method, i.e. building a map of AuthenticationTokens to AccessSets, and then
     * passing that to finishCacheReload(). 
     * 
     * This method avoids duplicate cache invalidations if invoked multiple times from multiple
     * sources (e.g. CAs in a cluster that broadcast a "clear caches" peer message). 
     * 
     * @param updateNumber Access tree update number at the time the clear cache triggered.
     * @return Currently existing AuthenticationTokens in the cache.
     */
    public static Set<AuthenticationToken> startCacheReload(final int updateNumber) {
        log.trace(">startCacheReload");
        synchronized (checkClearLock) {
            if (updateNumber != -1) {
                if (lastUpdate >= updateNumber) {
                    log.trace("<startCacheReload (already has a more recent version)");
                    return null;
                }
                lastUpdate = updateNumber;
                regularUpdateInProgress = true;
                log.debug("Started cache reload");
            } else if (regularUpdateInProgress) {
                log.trace("<startCacheReload (regular update was in progress)");
                return null;
            }
        }
        final Set<AuthenticationToken> existing = cache.getKeys();
        log.trace("<startCacheReload");
        return existing;
    }
    
    public static void finishCacheReload(final int updateNumber, final Map<AuthenticationToken,AccessSet> newCacheMap) {
        log.trace(">finishCacheReload");
        
        if (updateNumber != -1) {
            if (lastUpdate > updateNumber) {
                log.trace("<finishCacheReload (not updating because a more recent update finished earlier)");
                return;
            }
        } else if (regularUpdateInProgress) {
            log.trace("<finishCacheReload (not updating because regularUpdateInProgress)");
            return;
        }
        
        // Build new cache, but don't update it yet
        final ConcurrentCache<AuthenticationToken,AccessSet> newCache = new ConcurrentCache<>(newCacheMap, -1L);
        
        // Make sure we don't overwrite a more recent update (e.g. if it finished faster than us)
        synchronized (checkClearLock) {
            if (updateNumber != -1) {
                if (lastUpdate > updateNumber) {
                    log.trace("<finishCacheReload (already has a more recent version)");
                    return;
                }
                lastUpdate = updateNumber;
                regularUpdateInProgress = false;
            } else if (regularUpdateInProgress) {
                log.trace("<finishCacheReload (regular update was in progress)");
                return;
            }
            cache = newCache;
            log.debug("Replaced access set cache");
        }
        log.trace("<finishCacheReload");
    }
    
}
