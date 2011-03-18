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

import junit.framework.TestCase;

/**
 * Tests the simple object cache class .
 * 
 * @version $Id$
 */
public class ObjectCacheTest extends TestCase {
	public void testObjectCache() throws Exception {
		ObjectCache<Object,Object> cache = new ObjectCache<Object,Object>(200);
		cache.put("foo", "bar");
		cache.put("foo1", "bar1");
		cache.put("foo2", "bar2");
		Object o = cache.get("foo1");
		assertNotNull(o);
		String s = (String)o;
		assertEquals("bar1", s);
		Thread.sleep(250);
		o = cache.get("foo1");
		assertNull(o);
		o = cache.get("foo");
		assertNull(o);
		o = cache.get("foo2");
		assertNull(o);
	}
}
