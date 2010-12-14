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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** A simple object cache that can be used to cache object for a limited time. By default object are cached for 5 seconds.
 * Uses synchronized collections.
 * 
 * @version $Id$
 */
public class ObjectCache {

	/** The objects */
	private final Map<Object, Object> objects;
	/** map holding expire times for the object, so we know when we should not cache them any more */
	private final Map<Object, Long> expire;

	/** expiration time in milliseconds*/
	private long expireTime;

	/**
	 * Constructor with default expire of 5 seconds.
	 */
	public ObjectCache() {
		this(5000);
	}

	/**
	 * Constructor with expire as argument.
	 * @param expireTime expiration time in milliseconds
	 */
	public ObjectCache(final long expireTime) {
		this.objects = Collections.synchronizedMap(new HashMap<Object, Object>());
		this.expire = Collections.synchronizedMap(new HashMap<Object, Long>());
		this.expireTime = expireTime;
	}

	/** empties the cache completely */
	public synchronized void emptyCache() {
		this.objects.clear();
		this.expire.clear();
	}
	/**
	 * Put an object into the cache, the expiration time will be set.
	 * 
	 * @param key the key for the object in the cache
	 * @param o the cached object
	 */
	public void put(final Object key, final Object o) {
		this.objects.put(key, o);
		this.expire.put(key, Long.valueOf(System.currentTimeMillis() + expireTime));
	}

	/**
	 * Returns an object from the cache.
	 * 
	 * @param key the key for the object in the cache
	 * @return the cached object
	 */
	public Object get(final Object key) {
		final Long expiresAt = (Long)this.expire.get(key);
		Object ret = null;
		if (expiresAt != null) {
			if (System.currentTimeMillis() < expiresAt) {
				return this.objects.get(key);
			} else {
				this.objects.remove(key);
				this.expire.remove(key);				
			}
		}
		return ret;
	}
}
