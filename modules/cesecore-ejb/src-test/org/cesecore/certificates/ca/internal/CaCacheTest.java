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
package org.cesecore.certificates.ca.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.config.ConfigurationHolder;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test the CA Cache behavior.
 * 
 * @version $Id$
 */
public class CaCacheTest {
    
    private static final transient Logger log = Logger.getLogger(CaCacheTest.class);

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
        ConfigurationHolder.updateConfiguration("cainfo.cachetime", "-1");
        final String name1 = CaCacheTest.class.getSimpleName() + " CA1";
        final String name2 = CaCacheTest.class.getSimpleName() + " CA2";
        final String name3 = CaCacheTest.class.getSimpleName() + " CA3";
        final CA ca1 = getNewCa("CN=" + name1);
        final CA ca2 = getNewCa("CN=" + name2);
        final CA ca3 = getNewCa("CN=" + name3);
        // Start out with an empty cache and verify state
        CaCache.INSTANCE.flush();
        assertEquals("Expected empty map after flush.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Add entries to the (disabled) cache
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, name1, ca1);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 1, name2, ca2);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 1, name3, ca3);
        assertEquals("Expected empty map for disabled cache.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Notify cache that the objects should be removed from the cache
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, null, null);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 1, null, ca2);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 1, name3, null);
        assertEquals("Expected empty map for after removing objects.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    /**
     * Verify that objects put in the cache are available from it and that the name to id mapping works.
     * Also verify that a change in the provided digest is required for any cache update to take place.
     */
    @Test
    public void enabledCacheBehavior() {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("cainfo.cachetime", "3000");
        final String name1 = CaCacheTest.class.getSimpleName() + " CA1";
        final String name2 = CaCacheTest.class.getSimpleName() + " CA2";
        final String name3 = CaCacheTest.class.getSimpleName() + " CA3";
        final CA ca1 = getNewCa("CN=" + name1);
        final CA ca2 = getNewCa("CN=" + name2);
        final CA ca3 = getNewCa("CN=" + name3);
        // Start out with an empty cache and verify state
        CaCache.INSTANCE.flush();
        assertEquals("Expected empty map after flush.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Add entries to the (enabled) cache
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, name1, ca1);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 1, name2, ca2);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 1, name3, ca3);
        assertEquals("Expected non-empty map for enabled cache.", 3, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertEquals("Wrong mapping for name.", ca1.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", ca2.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Wrong mapping for name.", ca3.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Expected cache to return same instance of object 1.", ca1, CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertEquals("Expected cache to return same instance of object 2.", ca2, CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertEquals("Expected cache to return same instance of object 3.", ca3, CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertFalse("Cache indicated that existing object is invalid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertFalse("Cache indicated that existing object is invalid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertFalse("Cache indicated that existing object is invalid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Update test with and without changing the digest
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, name2, ca2);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 2, name3, ca3);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 2, name2, ca2);
        assertEquals("Wrong mapping for name.", ca1.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", ca2.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Wrong mapping for name.", ca3.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Cache was updated even though digest didn't change.", ca1, CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertEquals("Cache wasn't updated even though digest did change.", ca3, CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertEquals("Cache wasn't updated even though digest did change.", ca2, CaCache.INSTANCE.getEntry(ca3.getCAId()));
        // Notify cache that the objects should be removed from the cache
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, null, null);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 1, null, ca2);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 1, name3, null);
        assertEquals("Expected empty map for after removing objects.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    /**
     * Verify that the objects we add to the cache is available even after the cache has expired,
     * but the caller is asked to fetch the data from the original source instead.
     */
    @Test
    public void cacheExpiration() throws InterruptedException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("cainfo.cachetime", "2000");
        final String name1 = CaCacheTest.class.getSimpleName() + " CA1";
        final String name2 = CaCacheTest.class.getSimpleName() + " CA2";
        final String name3 = CaCacheTest.class.getSimpleName() + " CA3";
        final CA ca1 = getNewCa("CN=" + name1);
        final CA ca2 = getNewCa("CN=" + name2);
        final CA ca3 = getNewCa("CN=" + name3);
        // Start out with an empty cache and verify state
        CaCache.INSTANCE.flush();
        assertEquals("Expected empty map after flush.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Add entries to the (enabled) cache
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, name1, ca1);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 1, name2, ca2);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 1, name3, ca3);
        assertEquals("Expected non-empty map for enabled cache.", 3, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertEquals("Wrong mapping for name.", ca1.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", ca2.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Wrong mapping for name.", ca3.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Expected cache to return same instance of object 1.", ca1, CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertEquals("Expected cache to return same instance of object 2.", ca2, CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertEquals("Expected cache to return same instance of object 3.", ca3, CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertFalse("Cache indicated that existing object is invalid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertFalse("Cache indicated that existing object is invalid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertFalse("Cache indicated that existing object is invalid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Wait until we are sure that the cache has expired
        Thread.sleep(2500L);
        assertEquals("Expected non-empty map for enabled cache.", 3, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertEquals("Wrong mapping for name.", ca1.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name1).intValue());
        assertEquals("Wrong mapping for name.", ca2.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name2).intValue());
        assertEquals("Wrong mapping for name.", ca3.getCAId(), CaCache.INSTANCE.getNameToIdMap().get(name3).intValue());
        assertEquals("Expected cache to return same instance of object 1.", ca1, CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertEquals("Expected cache to return same instance of object 2.", ca2, CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertEquals("Expected cache to return same instance of object 3.", ca3, CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that stale object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that stale object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that stale object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        // Notify cache that the objects should be removed from the cache
        CaCache.INSTANCE.updateWith(ca1.getCAId(), 1, null, null);
        CaCache.INSTANCE.updateWith(ca2.getCAId(), 1, null, ca2);
        CaCache.INSTANCE.updateWith(ca3.getCAId(), 1, name3, null);
        assertEquals("Expected empty map for after removing objects.", 0, CaCache.INSTANCE.getNameToIdMap().entrySet().size());
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca1.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca2.getCAId()));
        assertNull("Empty cache returned an entry anyway.", CaCache.INSTANCE.getEntry(ca3.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca1.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca2.getCAId()));
        assertTrue("Cache indicated that non-existing object is valid.", CaCache.INSTANCE.shouldCheckForUpdates(ca3.getCAId()));
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    private CA getNewCa(final String cadn) {
        final CAToken emptyCaToken = new CAToken(0, new Properties());
        final X509CAInfo cainfo = new X509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, 3650, CAInfo.SELFSIGNED, null, emptyCaToken);
        cainfo.setDescription("JUnit RSA CA");
        return new X509CA(cainfo);
    }
}
