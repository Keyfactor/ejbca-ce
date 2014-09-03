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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

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
    private Map<Integer, CacheEntry> cache = new HashMap<Integer, CacheEntry>();
    private Map<String, Integer> nameToIdMap = new HashMap<String, Integer>();

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
        final CacheEntry cacheEntry = cache.get(key);
        if (cacheEntry == null) {
            // No such object in cache, caller should check db
            return true;
        }
        if (cacheEntry.lastUpdate+cacheTime<now) {
            // We probably need to update, but re-check using synchronization
            synchronized (cacheEntry) {
                if (cacheEntry.lastUpdate+cacheTime<now) {
                    // Object is present in cache, but cache has expired so the caller should update the cache
                    // To prevent other threads to ask the database for the same thing, we reset the cache time.
                    cacheEntry.lastUpdate = now;
                    return true;
                }
            }
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
                    log.debug("Updated " + object.getClass().getSimpleName() + " cache. Digest was " + digest + ", cacheEntry digest was " + (cacheEntry == null ? "null" : cacheEntry.digest));
                }
            } else {
                // Cached object is fine. No action needed.
                if (log.isDebugEnabled()) {
                    log.debug("Did not update " + object.getClass().getSimpleName() + " cache. Digest was " + digest + ", cacheEntry digest was " + (cacheEntry == null ? "null" : cacheEntry.digest));
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
        return cache.get(key);
    }
    
    /** Set or remove cache entry. */
    private void setCacheEntry(final Integer key, final CacheEntry cacheEntry) {
        final Map<Integer, CacheEntry> cacheStage = new HashMap<Integer, CacheEntry>();
        final Map<String, Integer> nameToIdMapStage = new HashMap<String, Integer>();
        final long maxCacheLifeTime = getMaxCacheLifeTime();
        final long staleCutOffTime = System.currentTimeMillis()-maxCacheLifeTime;
        synchronized (this) {
            // Process all entries except for the one that will change
            for (final Entry<Integer,CacheEntry> entry : cache.entrySet()) {
                final Integer currentId = entry.getKey();
                if (!key.equals(currentId)) {
                    final CacheEntry currentCacheEntry = entry.getValue();
                    // By flushing older entries we at least limit how much
                    // this registry will grow when used for short-lived objects
                    // in a clustered environment.
                    if (maxCacheLifeTime<1 || currentCacheEntry.lastUpdate >= staleCutOffTime) {
                        // Keep using the current entry in the new cache
                        cacheStage.put(entry.getKey(), currentCacheEntry);
                        nameToIdMapStage.put(currentCacheEntry.name, entry.getKey());
                    }
                }
            }
            // Process the one that will change
            if (cacheEntry == null) {
                // Don't add if to the new version of the cache if it existed (e.g. remove it)
            } else {
                cacheStage.put(key, cacheEntry);
                nameToIdMapStage.put(cacheEntry.name, key);
            }
            cache = cacheStage;
            nameToIdMap = Collections.unmodifiableMap(nameToIdMapStage);
        }
    }

    @Override
    public Map<String,Integer> getNameToIdMap() {
        return nameToIdMap;
    }

    @Override
    public void flush() {
        final Map<Integer, CacheEntry> cacheStage = new HashMap<Integer, CacheEntry>();
        final Map<String, Integer> nameToIdMapStage = new HashMap<String, Integer>();
        replaceCache(cacheStage, nameToIdMapStage);
    }
    
    @Override
    public void replaceCacheWith(List<Integer> keys) {
        Map<Integer, CacheEntry> cacheStage = new HashMap<Integer, CacheEntry>();
        Map<String, Integer> nameToIdMapStage = new HashMap<String, Integer>();
        
        for(Integer key : keys) {
            CacheEntry entry = cache.get(key);
            cacheStage.put(key, entry);
            
            String name = entry.name;
            nameToIdMapStage.put(name, nameToIdMap.get(name));
        }
        
        replaceCache(cacheStage, nameToIdMapStage);
    }
    
    private void replaceCache(Map<Integer, CacheEntry> cacheStage, Map<String, Integer> nameToIdMapStage) {
        synchronized (this) {
            cache = cacheStage;
            nameToIdMap = nameToIdMapStage;
        }
    }
}