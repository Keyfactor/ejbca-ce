/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.era;

import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RaMasterApiQueryCache caches search result on CA nodes(supporting RAMasterApi backend) to support pagination.
 * It updates offset of discrete search criterias like CA, Certificate Profile and EE profile. This allows sort by
 * name instead of id. The cache is singleton and thread safe.
 * 
 * Later on, this cache may also be leveraged to limit number of search results during operations like certificate
 * synchronization. For example, if fetched results are searched and sorted ascending based on creation time; then 
 * we may introduce another constraint with where with creationTime > highest creation time on last search. This will 
 * allows smaller number of rows to sorted.
 * 
 */
public enum RaMasterApiQueryCache {
    INSTANCE;
        
    private static final int CACHE_ENTRY_TIMEOUT = 3600 * 1000;
    private static final int CACHE_MAX_IDLE_SIZE = 1000;
    
    public class CacheEntry {
        final long generationTime;
        final String query;
        Object queryResult;
        
        public CacheEntry(long generationTime, String query) {
            this.generationTime = generationTime;
            this.query = query;
        }

        public Object getQueryResult() {
            return queryResult;
        }

        public void setQueryResult(Object queryResult) {
            this.queryResult = queryResult;
        }

        public long getGenerationTime() {
            return generationTime;
        }

        public String getQuery() {
            return query;
        }
        
    }
    
    private final ConcurrentHashMap<Integer, CacheEntry> cache = new ConcurrentHashMap<>(100);
    
    public void updateCache(String query, Object response) {
        CacheEntry entry = new CacheEntry(System.currentTimeMillis(), query);
        entry.setQueryResult(response);
        cache.put(query.hashCode(), entry);
    }
    
    public void evictCacheEntry(String query) {
        cache.remove(query.hashCode());
    }
    
    public void evictStaleCacheEntries() {
        if(cache.size() < CACHE_MAX_IDLE_SIZE) {
            return;
        }
        for(Entry<Integer, CacheEntry> entry: cache.entrySet()) {
            if(System.currentTimeMillis() - entry.getValue().getGenerationTime() > CACHE_ENTRY_TIMEOUT) {
                cache.remove(entry.getKey());
            }
        }
    }
    
    public Object getCachedResult(String query) {
        CacheEntry entry = cache.get(query.hashCode());
        if(entry!=null) {
            evictStaleCacheEntries();
            return entry.getQueryResult();
        }
        return null;
    }
        
}
