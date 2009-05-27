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
 * 
 * @version $Id$
 */
public class ObjectCache {

	/** The objects */
	private final Map objects;
	/** map holding expire times for the object, so we know when we should not cache them any more */
	private final Map expire;

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
	 * @param expire expiration time in milliseconds
	 */
	public ObjectCache(long expireTime) {
		this.objects = Collections.synchronizedMap(new HashMap());
		this.expire = Collections.synchronizedMap(new HashMap());
		this.expireTime = expireTime;
	}

	/**
	 * Put an object into the cache, the expiration time will be set.
	 * 
	 * @param key the key for the object in the cache
	 * @param o the cached object
	 */
	public void put(Object key, Object o) {
		this.objects.put(key, o);
		this.expire.put(key, Long.valueOf(System.currentTimeMillis() + expireTime));
	}

	/**
	 * Returns an object from the cache.
	 * 
	 * @param key the key for the object in the cache
	 * @return the cached object
	 */
	public Object get(Object key) {
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
