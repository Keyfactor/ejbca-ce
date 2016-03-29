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
package org.cesecore.util;

import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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
     * 
     * All methods are thread safe, but only one thread should operate on an Entry object.
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
        }
        
        private Entry(final K key, final InternalEntry<V> entry, final Object ourSemaphore) {
            if (ourSemaphore == null) {
                throw new IllegalArgumentException("ourSemaphore may not be null");
            }
            this.key = key;
            this.entry = entry;
            this.ourSemaphore = ourSemaphore;
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
         * Updates the value in this Entry as well as in the underlying cache.
         * The expire time is set to be "infinite". Thread-safe.
         */
        public void putValue(final V value) {
            if (key != null) {
                entry = new InternalEntry<>(value);
                cache.put(key, entry);
            }
        }
        
        /**
         * Sets the validity of the value. After the cache entry expires, the next request for it will
         * fail (on purpose) so it can be updated. Requests that happen while the expired entry is being
         * updated will still use the expired value, so they don't have to block.
         * @param validFor Cache validity in milliseconds.
         */
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
    
    private final ConcurrentHashMap<K,InternalEntry<V>> cache = new ConcurrentHashMap<>();
    private final ConcurrentMap<K,Object> semaphores = new ConcurrentHashMap<>();
    
    public static final long NO_LIMIT = -1L;
    
    /** @see #setEnabled */
    private volatile boolean enabled = true;
    
    /** @see setMaxEntries */
    private volatile long maxEntries = NO_LIMIT;
    
    private AtomicLong numEntries = new AtomicLong(0L);
    private final Set<K> pendingRemoval = Collections.newSetFromMap(new ConcurrentHashMap<K,Boolean>());
    private final Lock isCleaning = new ReentrantLock();
    private volatile long lastCleanup = 0L;
    private volatile long cleanupInterval = 1000L;
    
    /**
     * "Opens" a cache entry. If the entry already exists, then an {@link Entry} that
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
     * @throws NullPointerException if key is null.
     */
    public Entry openCacheEntry(final K key, final long timeout) {
        final long timeAtEntry = System.currentTimeMillis();
        if (key == null) {
            throw new NullPointerException("key may not be null");
        }
        
        if (!enabled) {
            return new Entry(null, null);
        }
        
        if (maxEntries != NO_LIMIT) {
            pendingRemoval.remove(key); // always mark as used
        }
        
        // Fast path if cached
        InternalEntry<V> entry = cache.get(key);
        final long toExpire = (entry != null ? entry.expire : 0L);
        if (entry != null && toExpire > timeAtEntry) {
            // Found valid entry in cache
            if (log.isDebugEnabled()) {
                log.debug("Found valid entry in cache for key "+key);
                log.trace("<ConcurrentCache.openCacheEntry");
            }
            cleanupIfNeeded();
            return new Entry(key, entry);
        } else if (entry != null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry has expired "+key+", expiry="+entry.expire);
            }
            numEntries.decrementAndGet();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Entry was not present in cache "+key);
            }
        }
        
        // Make sure only one thread enters "opens" the cache entry in write mode.
        // Subsequent attempts to open it will block until the first cache entry has been closed.
        final Object ourSemaphore = new Object();
        final Object theirSemaphore = semaphores.putIfAbsent(key, ourSemaphore);
        if (theirSemaphore == null) {
            // We were first
            numEntries.incrementAndGet();
            cleanupIfHighlyNeeded();
            return new Entry(key, null, ourSemaphore);
        }
        
        // Someone else was first
        
        // Check if we can return an existing entry (ECA-4936)
        if (entry != null) {
            log.debug("Returning existing cache entry for now");
            log.trace("<ConcurrentCache.openCacheEntry");
            cleanupIfNeeded();
            return new Entry(key, entry);
        }
        
        // Wait for a fresh entry to be created
        try {
            synchronized (theirSemaphore) {
                if (!cache.containsKey(key)) {
                    cleanupIfNeeded();
                    theirSemaphore.wait(timeout);
                    while (!cache.containsKey(key) && System.currentTimeMillis() < timeAtEntry+timeout) {
                        theirSemaphore.wait(timeout/10L+1L);
                    }
                }
            }
        } catch (InterruptedException e) {
            // NOPMD
        }
        
        // Return cached result from other thread, or null on failure
        entry = cache.get(key);
        if (log.isDebugEnabled()) {
            log.debug("Got "+ (entry != null ? entry.value : "null") + " after waiting for cache");
            log.trace("<ConcurrentCache.openCacheEntry");
        }
        return entry != null ? new Entry(key, entry) : null;
    }
    
    /**
     * <p>Enables or disables caching. If disabled, nothing will be cached and openCacheEntry will
     * always immediately return an non-existent entry (this may also cause concurrent attempts
     * to fetch/build/etc the same object).</p>
     * 
     * <p>Disabling the cache doesn't stop any currently "open" cache entries from being written to.</p>
     * 
     * <p>The default is enabled.</p>
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    /** @see ConcurrentCache#setEnabled */
    public boolean isEnabled() {
        return enabled;
    }
    
    /**
     * <p>Sets the desired maximum number of entries in the cache. This is not a
     * strict limit, and the cache may temporarily exceed this number.</p>
     * 
     * <p>The value {@link ConcurrentCache#NO_LIMIT} (-1) is the default.</p>
     */
    public void setMaxEntries(long maxEntries) {
        if (maxEntries == NO_LIMIT || maxEntries > 0L) {
            this.maxEntries = maxEntries;
        } else {
            throw new IllegalArgumentException("max entries must be either a positive value or -1");
        }
    }
    
    /** @see ConcurrentCache#setMaxEntries */
    public long getMaxEntries() {
        return maxEntries;
    }
    
    /**
     * Sets the minimum time in milliseconds between two cleanup runs.
     * 
     * The default is 1000 (= 1 second).
     */
    public void setCleanupInterval(long milliseconds) {
        cleanupInterval = milliseconds;
    }
    
    /** @see ConcurrentCache#setCleanupInterval */
    public long getCleanupInterval() {
        return cleanupInterval;
    }
    
    private void cleanupIfNeeded() {
        if (maxEntries != NO_LIMIT && numEntries.get() > maxEntries) {
            cleanup();
        }
    }
    
    private void cleanupIfHighlyNeeded() {
        // More than 1.5 times the limit 
        if (maxEntries != NO_LIMIT && 2L*numEntries.get() > 3L*maxEntries) {
            cleanup();
        }
    }
    
    /** Used internally for testing. */
    void checkNumberOfEntries(long min, long max) {
        long a = numEntries.get();
        long b = cache.size();
        if (a != b) {
            throw new IllegalStateException("cache.size() and numEntries does not match ("+a+" and "+b+")");
        }
        if (a < min) {
            throw new IllegalStateException("number of entries ("+a+") is less than minimum ("+min+").");
        }
        if (a > max) {
            throw new IllegalStateException("number of entries ("+a+") is greater than maximum ("+max+").");
        }
    }
    
    /**
     * Removes expired entries, and randomly selected entries that have not been used since the last call.
     */
    private void cleanup() {
        final long startTime = System.currentTimeMillis();
        if (startTime < lastCleanup+cleanupInterval || !isCleaning.tryLock()) {
            return;
        }
        try {
            final float ratioToRemove;
            final Random random;
            if (maxEntries == NO_LIMIT) {
                ratioToRemove = 0;
                random = null;
            } else {
                // Remove a bit extra
                ratioToRemove = Math.max(0.0F, 1.0F-0.8F*(float)maxEntries/(float)numEntries.get());
                
                // Remove items that have not been accessed since they were last marked as "pending removal"
                for (K key : pendingRemoval) {
                    cache.remove(key);
                    numEntries.decrementAndGet();
                }
                pendingRemoval.clear();
                random = new Random(System.nanoTime());
            }
            
            final long now = System.currentTimeMillis();
            final Iterator<Map.Entry<K,InternalEntry<V>>> iter = cache.entrySet().iterator();
            while (iter.hasNext()) {
                final Map.Entry<K,InternalEntry<V>> mapEntry = iter.next();
                if (mapEntry.getValue().expire <= now) {
                    iter.remove();
                    numEntries.decrementAndGet();
                } else if (maxEntries != NO_LIMIT && random.nextFloat() < ratioToRemove) {
                    pendingRemoval.add(mapEntry.getKey());
                }
            }
        } finally {
            isCleaning.unlock();
            
            final long endTime = System.currentTimeMillis();
            lastCleanup = endTime;
            if (log.isDebugEnabled()) {
                log.debug("Clean up took "+(endTime - startTime)+" ms");
            }
        }
    }
    
    /**
     * Removes all entries in the cache
     */
    public void clear() {
        cache.clear();
        numEntries.set(0L);
        pendingRemoval.clear();
        lastCleanup = 0L;
    }
    
}
