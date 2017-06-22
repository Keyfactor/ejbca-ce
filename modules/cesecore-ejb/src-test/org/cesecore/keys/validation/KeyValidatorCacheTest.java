/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test the key validator cache behavior.
 * 
 * @version $Id$
 */
public class KeyValidatorCacheTest {

    /** Class logger. */
    private static final transient Logger log = Logger.getLogger(KeyValidatorCacheTest.class);

    @BeforeClass
    public static void beforeClass() {
        ConfigurationHolder.instance();
    }

    /**
     * When caching is disabled (cachetime=-1) we expect that nothing sticks and that we always
     * are told to fetch the object from the original source instead of the cache.
     */
    @Test
    public void disabledCacheBehavior() {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("keyvalidator.cachetime", "-1");
        final String name1 = KeyValidatorCacheTest.class.getSimpleName() + " Publ1";
        final String name2 = KeyValidatorCacheTest.class.getSimpleName() + " Publ2";
        final String name3 = KeyValidatorCacheTest.class.getSimpleName() + " Publ3";
        final BaseKeyValidator keyValidator1 = getNewKeyValidator();
        final BaseKeyValidator keyValidator2 = getNewKeyValidator();
        final BaseKeyValidator keyValidator3 = getNewKeyValidator();
        // Start out with an empty cache and verify state
        KeyValidatorCache.INSTANCE.flush();
        assertEquals("Expected empty map after flush.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        // Add entries to the (disabled) cache
        // ECA-4219 Fix. Disable cache does not work.
        KeyValidatorCache.INSTANCE.updateWith(1, 1, name1, keyValidator1);
        KeyValidatorCache.INSTANCE.updateWith(2, 1, name2, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(3, 1, name3, keyValidator3);
        assertEquals("Expected empty map for disabled cache.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(2));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        // Notify cache that the objects should be removed from the cache
        KeyValidatorCache.INSTANCE.updateWith(1, 1, null, null);
        KeyValidatorCache.INSTANCE.updateWith(2, 1, null, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(3, 1, name3, null);
        assertEquals("Expected empty map for after removing objects.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(2));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    /**
     * Verify that objects put in the cache are available from it and that the name to id mapping works.
     * Also verify that a change in the provided digest is required for any cache update to take place.
     */
    @Test
    public void enabledCacheBehavior() {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("keyvalidator.cachetime", "3000");
        final String name1 = KeyValidatorCacheTest.class.getSimpleName() + " Publ1";
        final String name2 = KeyValidatorCacheTest.class.getSimpleName() + " Publ2";
        final String name3 = KeyValidatorCacheTest.class.getSimpleName() + " Publ3";
        final BaseKeyValidator keyValidator1 = getNewKeyValidator();
        final BaseKeyValidator keyValidator2 = getNewKeyValidator();
        final BaseKeyValidator keyValidator3 = getNewKeyValidator();
        // Start out with an empty cache and verify state
        KeyValidatorCache.INSTANCE.flush();
        assertEquals("Expected empty map after flush.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(2));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        // Add entries to the (enabled) cache
        KeyValidatorCache.INSTANCE.updateWith(1, 1, name1, keyValidator1);
        KeyValidatorCache.INSTANCE.updateWith(2, 1, name2, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(3, 1, name3, keyValidator3);
        assertEquals("Expected non-empty map for enabled cache.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertEquals("Wrong mapping for name.", 1, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", 2, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Wrong mapping for name.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Expected cache to return same instance of object 1.", keyValidator1, KeyValidatorCache.INSTANCE.getEntry(1));
        assertEquals("Expected cache to return same instance of object 2.", keyValidator2, KeyValidatorCache.INSTANCE.getEntry(2));
        assertEquals("Expected cache to return same instance of object 3.", keyValidator3, KeyValidatorCache.INSTANCE.getEntry(3));
        assertFalse("Cache indicated that existing object is invalid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertFalse("Cache indicated that existing object is invalid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertFalse("Cache indicated that existing object is invalid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertEquals("Wrong mapping for name", name1, KeyValidatorCache.INSTANCE.getName(1));
        assertEquals("Wrong mapping for name", name2, KeyValidatorCache.INSTANCE.getName(2));
        assertEquals("Wrong mapping for name", name3, KeyValidatorCache.INSTANCE.getName(3));
        // Update test with and without changing the digest
        KeyValidatorCache.INSTANCE.updateWith(1, 1, name2, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(2, 2, name3, keyValidator3);
        KeyValidatorCache.INSTANCE.updateWith(3, 2, name2, keyValidator2);
        assertEquals("Wrong mapping for name.", 1, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", 2, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Wrong mapping for name.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Cache was updated even though digest didn't change.", keyValidator1, KeyValidatorCache.INSTANCE.getEntry(1));
        assertEquals("Cache wasn't updated even though digest did change.", keyValidator3, KeyValidatorCache.INSTANCE.getEntry(2));
        assertEquals("Cache wasn't updated even though digest did change.", keyValidator2, KeyValidatorCache.INSTANCE.getEntry(3));
        assertEquals("Wrong mapping for name", name1, KeyValidatorCache.INSTANCE.getName(1));
        assertEquals("Wrong mapping for name", name3, KeyValidatorCache.INSTANCE.getName(2));
        assertEquals("Wrong mapping for name", name2, KeyValidatorCache.INSTANCE.getName(3));
        // Notify cache that the objects should be removed from the cache
        KeyValidatorCache.INSTANCE.updateWith(1, 1, null, null);
        KeyValidatorCache.INSTANCE.updateWith(2, 1, null, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(3, 1, name3, null);
        assertEquals("Expected empty map for after removing objects.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(2));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    /**
     * Verify that the objects we add to the cache is available even after the cache has expired,
     * but the caller is asked to fetch the data from the original source instead.
     */
    @Test
    public void cacheExpiration() throws InterruptedException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("keyvalidator.cachetime", "2000");
        final String name1 = KeyValidatorCacheTest.class.getSimpleName() + " CA1";
        final String name2 = KeyValidatorCacheTest.class.getSimpleName() + " CA2";
        final String name3 = KeyValidatorCacheTest.class.getSimpleName() + " CA3";
        final BaseKeyValidator keyValidator1 = getNewKeyValidator();
        final BaseKeyValidator keyValidator2 = getNewKeyValidator();
        final BaseKeyValidator keyValidator3 = getNewKeyValidator();
        // Start out with an empty cache and verify state
        KeyValidatorCache.INSTANCE.flush();
        assertEquals("Expected empty map after flush.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(2));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        // Add entries to the (enabled) cache
        KeyValidatorCache.INSTANCE.updateWith(1, 1, name1, keyValidator1);
        KeyValidatorCache.INSTANCE.updateWith(2, 1, name2, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(3, 1, name3, keyValidator3);
        assertEquals("Expected non-empty map for enabled cache.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertEquals("Wrong mapping for name.", 1, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", 2, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Wrong mapping for name.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Expected cache to return same instance of object 1.", keyValidator1, KeyValidatorCache.INSTANCE.getEntry(1));
        assertEquals("Expected cache to return same instance of object 2.", keyValidator2, KeyValidatorCache.INSTANCE.getEntry(2));
        assertEquals("Expected cache to return same instance of object 3.", keyValidator3, KeyValidatorCache.INSTANCE.getEntry(3));
        assertFalse("Cache indicated that existing object is invalid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertFalse("Cache indicated that existing object is invalid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertFalse("Cache indicated that existing object is invalid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertEquals("Wrong mapping for name", name1, KeyValidatorCache.INSTANCE.getName(1));
        assertEquals("Wrong mapping for name", name2, KeyValidatorCache.INSTANCE.getName(2));
        assertEquals("Wrong mapping for name", name3, KeyValidatorCache.INSTANCE.getName(3));
        // Wait until we are sure that the cache has expired
        Thread.sleep(2500L);
        assertEquals("Expected non-empty map for enabled cache.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertEquals("Wrong mapping for name.", 1, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", 2, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Wrong mapping for name.", 3, KeyValidatorCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Expected cache to return same instance of object 1.", keyValidator1, KeyValidatorCache.INSTANCE.getEntry(1));
        assertEquals("Expected cache to return same instance of object 2.", keyValidator2, KeyValidatorCache.INSTANCE.getEntry(2));
        assertEquals("Expected cache to return same instance of object 3.", keyValidator3, KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that stale object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that stale object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that stale object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertEquals("Wrong mapping for name", name1, KeyValidatorCache.INSTANCE.getName(1));
        assertEquals("Wrong mapping for name", name2, KeyValidatorCache.INSTANCE.getName(2));
        assertEquals("Wrong mapping for name", name3, KeyValidatorCache.INSTANCE.getName(3));
        // Notify cache that the objects should be removed from the cache
        KeyValidatorCache.INSTANCE.updateWith(1, 1, null, null);
        KeyValidatorCache.INSTANCE.updateWith(2, 1, null, keyValidator2);
        KeyValidatorCache.INSTANCE.updateWith(3, 1, name3, null);
        assertEquals("Expected empty map for after removing objects.", 0, KeyValidatorCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(1));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(2));
        assertNull("Empty cache returned an entry anyway.", KeyValidatorCache.INSTANCE.getEntry(3));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(1));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(2));
        assertTrue("Cache indicated that non-existing object is valid.", KeyValidatorCache.INSTANCE.shouldCheckForUpdates(3));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(1));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(2));
        assertNull("Empty cache returned a name anyway", KeyValidatorCache.INSTANCE.getName(3));
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    private BaseKeyValidator getNewKeyValidator() {
        return new RsaKeyValidator();
    }
}
