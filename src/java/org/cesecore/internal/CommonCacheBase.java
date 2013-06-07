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
package org.cesecore.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;

/**
 * Object and name to id lookup cache base implementation.
 * 
 * Note that this type of cache is not optimized for short-lived objects, but
 * will prevent memory leaks to some extent through checking for stale data
 * during updates.
 * 
 * @version $Id$
 */
public abstract class CommonCacheBase<T> implements CommonCache<T> {
    
    private class CacheEntry {
        long lastUpdate;
        final int digest;
        final String name;
        final T object;
        CacheEntry(long lastUpdate, int digest, String name, T object) {
            this.lastUpdate = lastUpdate;
            this.digest = digest;
            this.name = name;
            this.object = object;
        }
    }
    
    private final Logger log = Logger.getLogger(CommonCacheBase.class);
    private final ReentrantLock lock = new ReentrantLock(false);
    private final Map<Integer, CacheEntry> cache = new HashMap<Integer, CacheEntry>();
    private final Map<Integer, String> idToNameMap = new HashMap<Integer, String>();

    /** @return how long to cache objects in milliseconds. */
    protected abstract long getCacheTime();
    
    /** @return the maximum allowed time an object may reside in the cache before it is purged. 0 means live forever. */
    protected abstract long getMaxCacheLifeTime();

    @Override
    public T getEntry(final int id) {
        final CacheEntry cacheEntry = getCacheEntry(Integer.valueOf(id));
        if (cacheEntry == null) {
            return null;
        }
        if (log.isDebugEnabled()) {
            log.debug("Returning cached " + cacheEntry.object.getClass().getSimpleName() + " object. Digest was " + cacheEntry.digest);
        }
        return cacheEntry.object;
    }

    @Override
    public boolean shouldCheckForUpdates(final int id) {
        final long now = System.currentTimeMillis();
        final long cacheTime = getCacheTime();
        if (cacheTime<0) {
            // Cache is disabled, caller should check db
            return true;
        }
        final Integer key = Integer.valueOf(id);
        lock.lock();
        try {
            final CacheEntry cacheEntry = cache.get(key);
            if (cacheEntry == null) {
                // No such object in cache, caller should check db
                return true;
            }
            if (cacheEntry.lastUpdate+cacheTime<now) {
                // Object is present in cache, but cache has expired so the caller should update the cache
                // To prevent other threads to ask the database for the same thing, we reset the cache time.
                cacheEntry.lastUpdate = now;
                return true;
            }
        } finally {
            lock.unlock();
        }
        return false;
    }


    @Override
    public void removeEntry(int id) {
        updateWith(id, 0, null, null);
    }

    @Override
    public void updateWith(int id, int digest, String name, T object) {
        final Integer key = Integer.valueOf(id);
        if (name==null || object == null || getCacheTime()<0) {
            // Remove from cache
            setCacheEntry(key, null);
        } else {
            // Same version in cache as provided Object?
            final CacheEntry cacheEntry = getCacheEntry(key);
            if (cacheEntry == null || cacheEntry.digest != digest) {
                // Create new object and store it in the cache.
                final CacheEntry newCacheEntry = new CacheEntry(System.currentTimeMillis(), digest, name, object);
                setCacheEntry(key, newCacheEntry);
                if (log.isDebugEnabled()) {
                    log.debug("Updated " + object.getClass().getSimpleName() + " cache. Digest was " + digest + ", cacheEntry was " + cacheEntry);
                }
            } else {
                // Cached object is fine. No action needed.
                if (log.isDebugEnabled()) {
                    log.debug("Did not update " + object.getClass().getSimpleName() + " cache. Digest was " + digest + ", cacheEntry was " + cacheEntry);
                }
            }
        }
    }

    @Override
    public String getName(int id) {
        final CacheEntry entry = getCacheEntry(id);
        return entry != null ? entry.name : null;
    }
    
    /** @return cache entry for the requested key or null */
    private CacheEntry getCacheEntry(final Integer key) {
        lock.lock();
        try {
            return cache.get(key);
        } finally {
            lock.unlock(); 
        }
    }
    
    /** Set or remove cache entry. */
    private void setCacheEntry(final Integer key, final CacheEntry cacheEntry) {
        long maxCacheLifeTime = getMaxCacheLifeTime();
        lock.lock();
        try {
            if (cacheEntry == null) {
                cache.remove(key);
                idToNameMap.remove(key);
            } else {
                cache.put(key, cacheEntry);
                idToNameMap.put(key, cacheEntry.name);
                // By flushing older entries we at least limit how much
                // this registry will grow when used for short-lived objects
                // in a clustered environment.
                if (maxCacheLifeTime>0) {
                    flushStale(maxCacheLifeTime);
                }
            }
        } finally {
            lock.unlock(); 
        }
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
        final Map<String,Integer> ret = new HashMap<String,Integer>();
        lock.lock();
        try {
            for (final Integer key : idToNameMap.keySet()) {
                ret.put(idToNameMap.get(key), key);
            }
            return ret;
        } finally {
            lock.unlock(); 
        }
    }

    @Override
    public void flush() {
        lock.lock();
        try {
            cache.clear();
            idToNameMap.clear();
        } finally {
            lock.unlock(); 
        }
    }    

    /** Remove entries older than maxAge milliseconds. */
    private void flushStale(final long maxAge) {
        final long cutOff = System.currentTimeMillis()-maxAge;
        final List<Integer> toRemove = new ArrayList<Integer>();
        for (final Entry<Integer,CacheEntry> entry : cache.entrySet()) {
            if (entry.getValue().lastUpdate < cutOff) {
                toRemove.add(entry.getKey());
            }
        }
        for (final Integer key : toRemove) {
            cache.remove(key);
            idToNameMap.remove(key);
        }
    }
}