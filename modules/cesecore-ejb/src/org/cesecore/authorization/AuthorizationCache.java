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
package org.cesecore.authorization;

import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.ValidityDate;

/**
 * Cache of the authorization granted to different AuthenticationTokens.
 * 
 * Features:
 * - Concurrent cache misses for the same AuthenticationToken will only lead to a single call-back while the other threads wait
 * - Never return stale entries (when signaled that newer data might be available)
 * - Supports background reload via the rebuild(...) method which also purges unused entries
 * 
 * @version $Id$
 */
public enum AuthorizationCache {
    INSTANCE;
    
    private final Logger log = Logger.getLogger(AuthorizationCache.class);

    /** Call-back interface for loading access rules on cache miss */
    public interface AuthorizationCacheCallback {
        /** @return the access rules for the specified authenticationToken  */
        HashMap<String, Boolean> loadAccessRules(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

        /** @return the update number for the current state of roles and members used to determine if there are authorization changes */
        int getUpdateNumber();
        
        /** @return the number of milliseconds to keep cache entries for after an authentication token was last seen */
        long getKeepUnusedEntriesFor();
    }
    
    private class AuthorizationCacheEntry {
        HashMap<String, Boolean> accessRules;
        int updateNumber = 0;
        long timeOfLastUse = 0L;
        AuthenticationToken authenticationToken;
        final CountDownLatch countDownLatch = new CountDownLatch(1);
    }
    
    private ConcurrentHashMap<String, AuthorizationCacheEntry> cacheMap = new ConcurrentHashMap<>();
    private AtomicInteger latestUpdateNumber = new AtomicInteger(0);
    
    public void clear(final int updateNumber) {
        setUpdateNumberIfLower(updateNumber);
        cacheMap.clear();
    }

    /** Full reset should only be invoked by JUnit tests */
    protected void reset() {
        cacheMap.clear();
        latestUpdateNumber.set(0);
    }

    /** Re-build the authorization cache for all entries that been seen recently (as determined by authorizationCacheCallback.getKeepUnusedEntriesFor()). */
    public void refresh(final AuthorizationCacheCallback authorizationCacheCallback) {
        setUpdateNumberIfLower(authorizationCacheCallback.getUpdateNumber());
        final long purgeUnusedAuthorizationAfter = authorizationCacheCallback.getKeepUnusedEntriesFor();
        final long now = System.currentTimeMillis();
        final HashSet<String> existingKeysWhenInvoked = new HashSet<>(cacheMap.keySet());
        for (final String key : existingKeysWhenInvoked) {
            final AuthorizationCacheEntry entry = cacheMap.get(key);
            if (entry!=null) {
                if (entry.updateNumber<latestUpdateNumber.get()) {
                    // Newer access rules might be available
                    if (cacheMap.remove(key, entry)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Removed entry for key '" + key + "' since its updateNumber was " + entry.updateNumber + ".");
                        }
                        // Recalculate the authorization right away if this AuthenticationToken was seen recently
                        if (entry.timeOfLastUse+purgeUnusedAuthorizationAfter<now) {
                            try {
                                get(entry.authenticationToken, authorizationCacheCallback);
                            } catch (AuthenticationFailedException e) {
                                log.debug("Unexpected failure during refresh if authroization cache: " + e.getMessage());
                            }
                        }
                    }
                } else if (entry.timeOfLastUse+purgeUnusedAuthorizationAfter<now) {
                    // Remove the unused entry
                    if (cacheMap.remove(key, entry)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Removed entry for key '" + key + "' since it was last seen " + ValidityDate.formatAsUTC(entry.timeOfLastUse) + ".");
                        }
                    }
                }
            }
        }
    }

    /** @return the access rules granted to the specified authenticationToken using the callback to load them if needed. Never null.  */
    public HashMap<String, Boolean> get(final AuthenticationToken authenticationToken, final AuthorizationCacheCallback authorizationCacheCallback) throws AuthenticationFailedException {
        if (authenticationToken==null || authorizationCacheCallback==null) {
            return new HashMap<>();
        }
        final String key = authenticationToken.getUniqueId();
        final AuthorizationCacheEntry authorizationCacheEntry = new AuthorizationCacheEntry();
        AuthorizationCacheEntry ret = cacheMap.putIfAbsent(key, authorizationCacheEntry);
        if (ret == null) {
            ret = authorizationCacheEntry;
            try {
                ret.authenticationToken = authenticationToken;
                ret.updateNumber = authorizationCacheCallback.getUpdateNumber();
                setUpdateNumberIfLower(ret.updateNumber);
                ret.accessRules = new HashMap<>();
                final HashMap<String, Boolean> loadedAccessRules = authorizationCacheCallback.loadAccessRules(authenticationToken);
                if (loadedAccessRules != null) {
                    // Cache a copy of the loaded access rules map
                    ret.accessRules.putAll(loadedAccessRules);
                }
            } finally {
                // Ensure that we release any waiting thread
                ret.countDownLatch.countDown();
            }
            if (log.isDebugEnabled()) {
                log.debug("Added entry for key '" + key + "'.");
            }
        } else {
            try {
                // Block while it is loading (if it is still loading)
                ret.countDownLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            // Check if the returned entry is stale
            if (ret.updateNumber<latestUpdateNumber.get()) {
                // Trigger an update on next get and recurse
                if (cacheMap.remove(key, ret)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Removed entry for key '" + key + "' since its updateNumber was " + ret.updateNumber + ".");
                    }
                }
                return get(authenticationToken, authorizationCacheCallback);
            }
            // Don't care about last time of use here, just be happy that it was found if it was found 
        }
        // Weak indication of last use, so rebuild can eventually purge unused entries
        ret.timeOfLastUse = System.currentTimeMillis();
        return ret.accessRules;
    }

    /** Non-blocking atomic update of the last known update number. */
    private void setUpdateNumberIfLower(final int readUpdateNumber) {
        int current;
        while ((current = latestUpdateNumber.get()) < readUpdateNumber) {
            if (latestUpdateNumber.compareAndSet(current, readUpdateNumber)) {
                if (log.isDebugEnabled()) {
                    log.debug("latestUpdateNumber is now " + readUpdateNumber + ".");
                }
            }
        }
    }
}
