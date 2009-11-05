/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import org.apache.log4j.Logger;

/**
 * Cache that keeps track of requests and adds a part of them to the cache if requested to.
 * 
 * Used by ProtectedLogSession to avoid iterating over the same interval several times.
 * 
 * @version $Id$
 */
public class ManualUpdateCache {

	private static final Logger log = Logger.getLogger(ManualUpdateCache.class);
	private static final HashMap caches = new HashMap(); // <HashSet>
	private static final int MAX_CACHE_SIZE = 500;
	
	private static int maxCountBetweenCached = 10;

	private final HashSet localAddon = new HashSet(); // <CacheItem>

	private String cacheId = null;
	private int noHitCounter = 0;
	
	private ManualUpdateCache(String cacheId) {
		this.cacheId = cacheId;
	}
	
	/**
	 * @return a copy of the current cache
	 */
	public static ManualUpdateCache getNewInstance(String cacheId) {
		if (caches.get(cacheId) == null) {
			caches.put(cacheId, new HashSet());
		}
		return new ManualUpdateCache(cacheId);
	}
	
	private static void commitNew(String cacheId, HashSet localAddon) {	// <CacheItem>
		HashSet cache = (HashSet) caches.get(cacheId);
		synchronized(cache) {
			// Try to automatically tune performance of cache
			if (localAddon.size() * 100 / MAX_CACHE_SIZE > 10) {	// If incoming is more than X % of data 
				maxCountBetweenCached += maxCountBetweenCached * 20 / 100;	// Inc space between cached values with Y % each time this happens
				if (log.isDebugEnabled()) {
					log.debug("Increased space between cached rows to " + maxCountBetweenCached);
				}
			}
			// Add new items
			cache.addAll(localAddon);
			localAddon.clear();
			// Throw away least used items in cache
			final HashSet removalSet = new HashSet();
			final Random random = new Random(System.currentTimeMillis());
			while (cache.size() > MAX_CACHE_SIZE) {
				removalSet.clear();
				Iterator iter = cache.iterator();
				while (iter.hasNext()) {
					if (cache.size() -  removalSet.size() <= MAX_CACHE_SIZE) {
						break;
					}
					CacheItem cacheItem = (CacheItem) iter.next();
					if (cacheItem.getNumberOfHits() == 0 && random.nextBoolean()) {
						removalSet.add(cacheItem);
					}
					cacheItem.decreaseNumberOfHits();
				}
				if (log.isDebugEnabled()) {
					log.debug("Removing " + removalSet.size() + " items from cache."+ cache.size() + " " + localAddon.size());
				}
				cache.removeAll(removalSet);
			}
		}
	}
	
	private static boolean isPresentInCache(String cacheId, CacheItem cacheItem) {
		HashSet cache = (HashSet) caches.get(cacheId);
		synchronized(cache) {
			if (cache.contains(cacheItem)) {
				return true;
			}
			return false;
		}
	}

	/**
	 * @return true if the item is present in the cache.
	 */
	public boolean isPresent(Object object) {
		if (isPresentInCache(cacheId, new CacheItem(object))) {
			noHitCounter = 0;
			return true;
		}
		noHitCounter++;
		if (noHitCounter > maxCountBetweenCached && localAddon.size() < MAX_CACHE_SIZE) {
			localAddon.add(new CacheItem(object));
			noHitCounter = 0;
		}
		return false;
	}

	/**
	 * Mark all the requested data up to this point as valid.
	 */
	public void updateCache() {
		commitNew(cacheId, localAddon);
	}
	
	private class CacheItem {
		private Object object = null;
		private long numberOfHits = 1;	// Make sure new objects doesn't dissapear directly.
		
		public CacheItem(Object row) {
			this.object = row;
		}
		
		public Object getObject () {
			return object; 
		}

		public long getNumberOfHits() {
			return numberOfHits;
		}

		public void decreaseNumberOfHits() {
			if (numberOfHits > 0) {
				numberOfHits--;
			}
		}
		
		public int hashCode() {
			return object.hashCode();
		}
		
		public boolean equals(Object o) {
			return o instanceof CacheItem && equals((CacheItem) o);
		}

		private boolean equals(CacheItem cacheItem) {
			if (this.getObject().equals(cacheItem.getObject())) {
				numberOfHits += 2;
				return true;
			}
			return false;
		}
	}
}
