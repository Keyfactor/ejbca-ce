package org.cesecore.util;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.log4j.Logger;

/**
 * A concurrent cache allows multiple threads to cache data. Only one thread
 * will be allowed to generate data for one particular key, and other threads
 * will block.
 * 
 * All methods in this class and inner classes are thread-safe.
 * 
 * @version $Id$
 *
 */
public final class ConcurrentCache<K,V> {

    private static final Logger log = Logger.getLogger(ConcurrentCache.class);
    
    /**
     * Internal entries are stored in the ConcurrentMap
     */
    private final static class InternalEntry<V> {
        final V value;
        volatile long expire;
        
        private InternalEntry(final V value) {
            this.value = value;
            this.expire = Long.MAX_VALUE;
        }
    }
    
    /**
     * A reference to a cache entry, with a get and put method to read/write data from/to the cache.
     */
    public final class Entry {
        private final K key;
        private InternalEntry<V> entry;
        /** If non-null, then other threads are waiting on this semaphore for data on the same key in the cache. */
        private final Object ourSemaphore;
        
        private Entry(final K key, final InternalEntry<V> entry) {
            this.key = key;
            this.entry = entry;
            this.ourSemaphore = null;
            long systime = System.currentTimeMillis();
            if (entry != null && entry.expire < systime)
                throw new IllegalStateException("WTF 1, expiry was "+entry.expire+"  system time was "+systime);
        }
        
        private Entry(final K key, final InternalEntry<V> entry, final Object ourSemaphore) {
            if (ourSemaphore == null) {
                throw new IllegalArgumentException("ourSemaphore may not be null");
            }
            this.key = key;
            this.entry = entry;
            this.ourSemaphore = ourSemaphore;
            if (entry != null && entry.expire < System.currentTimeMillis())
                throw new IllegalStateException("WTF 2, expiry was "+entry.expire);
        }
        
        /**
         * @return true if the key existed in the cache.
         */
        public boolean isInCache() {
            return entry != null;
        }
        
        /**
         * @return the value read from the cache when the Entry was created. Calls to putValue() on this particular Entry change the return value.
         */
        public V getValue() {
            if (entry == null) {
                throw new IllegalStateException("Tried to read from non-existent cache entry");
            }
            return entry.value;
        }
        
        /**
         * Updates the value in this Entry as well as in the underlying cache. Thread-safe.
         */
        public void putValue(final V value) {
            entry = new InternalEntry<V>(value);
            cache.put(key, entry);
        }
        
        public void setCacheValidity(long validFor) {
            if (entry != null) {
                entry.expire = System.currentTimeMillis() + validFor;
            }
        }
        
        /**
         * Must be called if other threads might be waiting for this cache entry
         * (i.e. if isInCache() returns false)
         */
        public void close() {
            if (ourSemaphore != null) {
                synchronized (ourSemaphore) {
                    semaphores.remove(key);
                    ourSemaphore.notifyAll();
                }
            }
        }
    }
    
    private final ConcurrentHashMap<K,InternalEntry<V>> cache = new ConcurrentHashMap<K,InternalEntry<V>>();
    private final ConcurrentMap<K,Object> semaphores = new ConcurrentHashMap<K,Object>();
    
    /**
     * "Opens" a cache entry. If the entry already exists, then an Entry that
     * maps to the existing entry is returned. Otherwise, a semaphore is used
     * to prevent multiple threads from creating the new cache entry. Only the
     * first thread is returned an Entry with isInCache()==false, later threads
     * will block and wait for the first thread.
     * 
     * For non-existent entries (i.e. isInCache()==false), the caller is expected to put
     * a value in it and call close() on the Entry.
     *  
     * @param key      Key in the cache.
     * @param timeout  Timeout in milliseconds. The call will only be allowed
     *                 to block for (approximately) this amount of time.
     * @return An Entry object that maps to an entry in the cache (existing
     *         or blank), or null if a timeout occurred. 
     */
    public Entry openCacheEntry(final K key, final long timeout) {
        final long timeAtEntry = System.currentTimeMillis();
        
        // Fast path if cached
        InternalEntry<V> entry = cache.get(key);
        final long toExpire = (entry != null ? entry.expire : 0);
        if (entry != null && toExpire > timeAtEntry) {
            // Found valid entry in cache
            if (log.isDebugEnabled()) {
                log.debug("Found valid entry in cache for key "+key);
                log.trace("<ConcurrentCacheMap.openCacheEntry");
            }
            return new Entry(key, entry);
        } else if (log.isDebugEnabled()) {
            if (entry != null) {
                log.debug("Cache entry has expired "+key);
            } else {
                log.debug("Entry was not present in cache "+key);
            }
        }
        
        // Make sure only one thread enters "opens" the cache entry in write mode.
        // Subsequent attempts to open it will block until the first cache entry has been closed.
        final Object ourSemaphore = new Object();
        final Object theirSemaphore = semaphores.putIfAbsent(key, ourSemaphore);
        if (theirSemaphore == null) {
            // We were first
            return new Entry(key, null, ourSemaphore);
        }
        
        // Someone else was first
        try {
            synchronized (theirSemaphore) {
                if (!cache.containsKey(key)) {
                    theirSemaphore.wait(timeout);
                    while (!cache.containsKey(key) && System.currentTimeMillis() < timeAtEntry+timeout) {
                        theirSemaphore.wait(timeout/10+1);
                    }
                }
            }
        } catch (InterruptedException e) {
            // NOPMD
        }
        
        // Return cached result from other thread, or null on failure
        entry = cache.get(key);
        if (log.isDebugEnabled()) {
            log.debug("Got "+entry.value+" after waiting for cache");
            log.trace("<ConcurrentCacheMap.openCacheEntry");
        }
        return entry != null ? new Entry(key, entry) : null;
    }
    
    /**
     * Manually removes expired entries.
     */
    public void cleanup() {
        final long now = System.currentTimeMillis();
        //for (Map.Entry<K,InternalEntry<V>> mapEntry : cache.entrySet()) {
        final Iterator<Map.Entry<K,InternalEntry<V>>> iter = cache.entrySet().iterator();
        while (iter.hasNext()) {
            final Map.Entry<K,InternalEntry<V>> mapEntry = iter.next();
            if (mapEntry.getValue().expire <= now) {
                iter.remove();
            }
        }
    }
    
    /**
     * Removes all entries in the cache
     */
    public void clear() {
        cache.clear();
    }
    
}
