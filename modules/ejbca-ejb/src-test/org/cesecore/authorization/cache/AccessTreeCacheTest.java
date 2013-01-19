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
package org.cesecore.authorization.cache;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.roles.RoleData;
import org.junit.Test;

/**
 * Unit tests for the AccessTreeCache class.
 * 
 * @version $Id$
 * 
 */
public class AccessTreeCacheTest {

    /**
     * Tests the needsUpdate method.
     * 
     * @throws NoSuchFieldException
     * @throws SecurityException
     * @throws IllegalAccessException
     * @throws IllegalArgumentException
     */
    @Test
    public void testNeedsUpdate() {

        AccessTreeCache accessTreeCache = new AccessTreeCache();
        assertNull(accessTreeCache.getAccessTree());
        // Check that we get false before AccessTreeCache has had a chance to build a AccessTree.
        assertTrue("AccessTreeCache didn't answer that an update was required when accessTree == null", accessTreeCache.needsUpdate());
    }

    /**
     * Test updating the access tree, and note if needsUpdate acts correspondingly.
     * 
     * @throws SecurityException
     * @throws NoSuchFieldException
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     */
    @Test
    public void testUpdateAccessTree() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        int authorizationTreeUpdateNumber = 0;
        // Now build the access tree, make sure that it's not null but not ripe to be updated.
        AccessTreeCache accessTreeCache = new AccessTreeCache();
        Collection<RoleData> roles = new ArrayList<RoleData>();
        accessTreeCache.updateAccessTree(roles, authorizationTreeUpdateNumber++);
        assertTrue(accessTreeCache.getAccessTree() != null && !accessTreeCache.needsUpdate());

        // Now, using satanic magic and/or reflection, set the timervalue back a smidge and test again.
        Field lastUpdateTimeField = accessTreeCache.getClass().getDeclaredField("lastUpdateTime");
        lastUpdateTimeField.setAccessible(true);
        long newUpdateTime = lastUpdateTimeField.getLong(accessTreeCache) - CesecoreConfiguration.getCacheAuthorizationTime();
        lastUpdateTimeField.set(accessTreeCache, newUpdateTime);
        // And run the same test again, expecting a different result.
        assertTrue(accessTreeCache.getAccessTree() != null && accessTreeCache.needsUpdate());
        accessTreeCache.updateAccessTree(roles, authorizationTreeUpdateNumber++);
        assertTrue(accessTreeCache.getAccessTree() != null && !accessTreeCache.needsUpdate());
    }

}
