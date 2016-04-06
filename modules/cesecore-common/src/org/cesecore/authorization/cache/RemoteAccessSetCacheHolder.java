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

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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

    private static volatile int lastUpdate = -1;
    private static final Object checkClearLock = new Object();
    private static final Lock doClearLock = new ReentrantLock();
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
    
    /**
     * Clears 
     * @param updateNumber 
     */
    public static void clear(final int updateNumber) {
        log.trace(">clear");
        if (updateNumber != -1) {
            synchronized (checkClearLock) {
                if (lastUpdate >= updateNumber) {
                    log.trace("<clear");
                    return;
                }
                lastUpdate = updateNumber;
            }
        }
        if (doClearLock.tryLock()) {
            try {
                log.debug("Updating cache");
                doClear();
            } finally {
                doClearLock.unlock();
            }
        }
        log.trace("<clear");
    }
    
    private static void doClear() {
        log.trace(">doClear");
        // TODO do a background reload of PublicWebAuth
        cache.clear();
        log.trace("<doClear");
    }
    
}
