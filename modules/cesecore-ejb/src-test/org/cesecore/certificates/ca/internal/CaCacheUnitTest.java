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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.config.ConfigurationHolder;
import org.junit.Before;
import org.junit.Test;

/**
 * Test the CA Cache behavior.
 * 
 * @version $Id$
 */
public class CaCacheUnitTest {
    
    private static final transient Logger log = Logger.getLogger(CaCacheUnitTest.class);

    // CA names
    private static final String[] CA_NAMES = new String[] {
            "CaCacheUnitTest CA1",
            "CaCacheUnitTest CA2",
            "CaCacheUnitTest CA3"
    };
    // CA commons with binding to CA_NAMES
    private static final CACommon[] CAS = new CACommon[] {
            getCaCommon("CN=" + CA_NAMES[0]),
            getCaCommon("CN=" + CA_NAMES[1]),
            getCaCommon("CN=" + CA_NAMES[2])
    };

    @Before
    public void before() {
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
        final CaCache caCache = CaCache.INSTANCE;

        // Start out with an empty cache and verify state
        caCache.flush();
        assertEmptyCaCache();

        // Add entries to the (disabled) cache
        caCache.updateWith(CAS[0].getCAId(), 1, CA_NAMES[0], CAS[0]);
        caCache.updateWith(CAS[1].getCAId(), 1, CA_NAMES[1], CAS[1]);
        caCache.updateWith(CAS[2].getCAId(), 1, CA_NAMES[2], CAS[2]);
        assertEmptyCaCache();

        // Notify cache that the objects should be removed from the cache
        caCache.updateWith(CAS[0].getCAId(), 1, null, null);
        caCache.updateWith(CAS[1].getCAId(), 1, null, CAS[1]);
        caCache.updateWith(CAS[2].getCAId(), 1, CA_NAMES[2], null);
        assertEmptyCaCache();

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
        final CaCache caCache = CaCache.INSTANCE;

        // Start out with an empty cache and verify state
        caCache.flush();
        assertEmptyCaCache();

        // Add entries to the (enabled) cache
        caCache.updateWith(CAS[0].getCAId(), 1, CA_NAMES[0], CAS[0]);
        caCache.updateWith(CAS[1].getCAId(), 1, CA_NAMES[1], CAS[1]);
        caCache.updateWith(CAS[2].getCAId(), 1, CA_NAMES[2], CAS[2]);
        assertOrderedDataInCaCache(false);

        // Update test with and without changing the digest
        caCache.updateWith(CAS[0].getCAId(), 1, CA_NAMES[1], CAS[1]);
        caCache.updateWith(CAS[1].getCAId(), 2, CA_NAMES[2], CAS[2]);
        caCache.updateWith(CAS[2].getCAId(), 2, CA_NAMES[1], CAS[1]);
        // Should not be replaced
        assertCaCacheEntry(CAS[0].getCAId(), CA_NAMES[0], CAS[0], false);
        // Should be replaced
        assertCaCacheEntry(CAS[1].getCAId(), CA_NAMES[2], CAS[2], false);
        // Should be replaced
        assertCaCacheEntry(CAS[2].getCAId(), CA_NAMES[1], CAS[1], false);

        // Notify cache that the objects should be removed from the cache
        caCache.updateWith(CAS[0].getCAId(), 1, null, null);
        caCache.updateWith(CAS[1].getCAId(), 1, null, CAS[1]);
        caCache.updateWith(CAS[2].getCAId(), 1, CA_NAMES[2], null);
        assertEmptyCaCache();

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
        final CaCache caCache = CaCache.INSTANCE;

        // Start out with an empty cache and verify state
        caCache.flush();
        assertEmptyCaCache();

        // Add entries to the (enabled) cache
        CaCache.INSTANCE.updateWith(CAS[0].getCAId(), 1, CA_NAMES[0], CAS[0]);
        CaCache.INSTANCE.updateWith(CAS[1].getCAId(), 1, CA_NAMES[1], CAS[1]);
        CaCache.INSTANCE.updateWith(CAS[2].getCAId(), 1, CA_NAMES[2], CAS[2]);
        assertOrderedDataInCaCache(false);

        // Wait until we are sure that the cache has expired
        Thread.sleep(2500L);
        assertOrderedDataInCaCache(true);

        // Notify cache that the objects should be removed from the cache
        CaCache.INSTANCE.updateWith(CAS[0].getCAId(), 1, null, null);
        CaCache.INSTANCE.updateWith(CAS[1].getCAId(), 1, null, CAS[1]);
        CaCache.INSTANCE.updateWith(CAS[2].getCAId(), 1, CA_NAMES[2], null);
        assertEmptyCaCache();

        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    private static CACommon getCaCommon(final String caDn) {
        final CAToken emptyCaToken = new CAToken(0, new Properties());
        final X509CAInfo caInfo = X509CAInfo.getDefaultX509CAInfo(
                caDn, "TEST", CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA,
                "3650d", CAInfo.SELFSIGNED, null, emptyCaToken);
        caInfo.setDescription("JUnit RSA CA");
        return CAFactory.INSTANCE.getX509CAImpl(caInfo);
    }

    private void assertEmptyCaCache() {
        final CaCache caCache = CaCache.INSTANCE;
        assertEquals("Expected empty cache.", 0, caCache.getNameToIdMap().entrySet().size());
        for(int index = 0; index < CA_NAMES.length; index++) {
            final int caId = CAS[index].getCAId();
            assertNull("Empty cache returned an entry anyway for id [" + caId + "].", caCache.getEntry(caId));
            assertTrue("Cache indicated that non-existing object with id [" + caId + "] is valid.", caCache.shouldCheckForUpdates(caId));
            assertNull("Empty cache returned a name anyway for id [" + caId + "]", caCache.getName(caId));
        }
    }

    private void assertOrderedDataInCaCache(final boolean cacheEntryExpired) {
        final CaCache caCache = CaCache.INSTANCE;
        assertEquals("Expected cache map [" + CA_NAMES.length + "].", CA_NAMES.length, caCache.getNameToIdMap().entrySet().size());
        for(int index = 0; index < CA_NAMES.length; index++) {
            assertCaCacheEntry(CAS[index].getCAId(), CA_NAMES[index], CAS[index], cacheEntryExpired);
        }
    }

    private void assertCaCacheEntry(final int cacheId, final String caName, final CACommon caCommon, final boolean cacheEntryExpired) {
        final CaCache caCache = CaCache.INSTANCE;
        assertEquals(
                "Wrong mapping by name for name [" + caName + "] with id [" + cacheId + "]",
                cacheId,
                caCache.getNameToIdMap().get(caName).intValue()
        );
        assertEquals(
                "Expected cache to return same instance of object [" + caCommon + "].",
                caCommon,
                caCache.getEntry(cacheId)
        );
        assertEquals(
                "Cache indicated that existing object with id [" + cacheId + "] is " + (cacheEntryExpired ? "valid" : "invalid"),
                cacheEntryExpired,
                caCache.shouldCheckForUpdates(cacheId)
        );
        assertEquals(
                "Wrong mapping by id for name [" + caName + "] with id [" + cacheId + "]",
                caName,
                caCache.getName(cacheId)
        );
    }
}
