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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;
import org.junit.Before;
import org.junit.Test;

/**
 * Test the key validator cache behavior.
 * 
 * @version $Id$
 */
public class KeyValidatorCacheUnitTest {

    private static final transient Logger log = Logger.getLogger(KeyValidatorCacheUnitTest.class);

    // Validator names
    private static final String[] VALIDATOR_NAMES = new String[]{
            "KeyValidatorCacheUnitTest Publ1",
            "KeyValidatorCacheUnitTest Publ2",
            "KeyValidatorCacheUnitTest Publ3"
    };
    // Validators with binding to VALIDATOR_NAMES
    private static final ValidatorBase[] VALIDATORS = new ValidatorBase[]{
            new RsaKeyValidator(VALIDATOR_NAMES[0]),
            new RsaKeyValidator(VALIDATOR_NAMES[1]),
            new RsaKeyValidator(VALIDATOR_NAMES[2])
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
        ConfigurationHolder.updateConfiguration("validator.cachetime", "-1");
        final ValidatorCache validatorCache = ValidatorCache.INSTANCE;

        // Start out with an empty cache and verify state
        validatorCache.flush();
        assertEmptyValidatorCache();

        // Add entries to the (disabled) cache
        for(int index = 0; index < VALIDATOR_NAMES.length; index++) {
            validatorCache.updateWith(index, 1, VALIDATOR_NAMES[index], VALIDATORS[index]);
        }
        assertEmptyValidatorCache();

        // Notify cache that the objects should be removed from the cache
        validatorCache.updateWith(0, 1, null, null);
        validatorCache.updateWith(1, 1, null, VALIDATORS[1]);
        validatorCache.updateWith(2, 1, VALIDATOR_NAMES[2], null);
        assertEmptyValidatorCache();

        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    /**
     * Verify that objects put in the cache are available from it and that the name to id mapping works.
     * Also verify that a change in the provided digest is required for any cache update to take place.
     */
    @Test
    public void enabledCacheBehavior() {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("validator.cachetime", "3000");
        final ValidatorCache validatorCache = ValidatorCache.INSTANCE;

        // Start out with an empty cache and verify state
        validatorCache.flush();
        assertEmptyValidatorCache();

        // Add entries to the (enabled) cache
        for(int index = 0; index < VALIDATOR_NAMES.length; index++) {
            validatorCache.updateWith(index, 1, VALIDATOR_NAMES[index], VALIDATORS[index]);
        }
        // Should be in the same order 0, 1, 2
        assertOrderedDataInValidatorCache(false);

        // Update test with and without changing the digest
        validatorCache.updateWith(0, 1, VALIDATOR_NAMES[1], VALIDATORS[1]);
        validatorCache.updateWith(1, 2, VALIDATOR_NAMES[2], VALIDATORS[2]);
        validatorCache.updateWith(2, 2, VALIDATOR_NAMES[1], VALIDATORS[1]);
        // Should not be replaced
        assertValidatorCacheEntry(0, VALIDATOR_NAMES[0], VALIDATORS[0], false);
        // Should be replaced
        assertValidatorCacheEntry(1, VALIDATOR_NAMES[2], VALIDATORS[2], false);
        // Should be replaced
        assertValidatorCacheEntry(2, VALIDATOR_NAMES[1], VALIDATORS[1], false);

        // Notify cache that the objects should be removed from the cache
        validatorCache.updateWith(0, 1, null, null);
        validatorCache.updateWith(1, 1, null, VALIDATORS[1]);
        validatorCache.updateWith(2, 1, VALIDATOR_NAMES[2], null);
        assertEmptyValidatorCache();
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    /**
     * Verify that the objects we add to the cache is available even after the cache has expired,
     * but the caller is asked to fetch the data from the original source instead.
     */
    @Test
    public void cacheExpiration() throws InterruptedException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        ConfigurationHolder.updateConfiguration("validator.cachetime", "2000");
        final ValidatorCache validatorCache = ValidatorCache.INSTANCE;

        // Start out with an empty cache and verify state
        validatorCache.flush();
        assertEmptyValidatorCache();

        // Add entries to the (enabled) cache
        for(int index = 0; index < VALIDATOR_NAMES.length; index++) {
            validatorCache.updateWith(index, 1, VALIDATOR_NAMES[index], VALIDATORS[index]);
        }
        // Should be in the same order 0, 1, 2
        assertOrderedDataInValidatorCache(false);

        // Wait until we are sure that the cache has expired
        Thread.sleep(2500L);
        // Should be in the same order 0, 1, 2
        assertOrderedDataInValidatorCache(true);

        // Notify cache that the objects should be removed from the cache
        validatorCache.updateWith(0, 1, null, null);
        validatorCache.updateWith(1, 1, null, VALIDATORS[1]);
        validatorCache.updateWith(2, 1, VALIDATOR_NAMES[2], null);
        assertEmptyValidatorCache();

        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }

    private void assertEmptyValidatorCache() {
        final ValidatorCache validatorCache = ValidatorCache.INSTANCE;
        assertEquals("Expected empty cache.", 0, validatorCache.getNameToIdMap().entrySet().size());
        for(int index = 0; index < VALIDATOR_NAMES.length; index++) {
            assertNull("Empty cache returned an entry anyway for id [" + index + "].", validatorCache.getEntry(index));
            assertTrue("Cache indicated that non-existing object with id [" + index + "] is valid.", validatorCache.shouldCheckForUpdates(index));
            assertNull("Empty cache returned a name anyway for id [" + index + "]", validatorCache.getName(index));
        }
    }

    private void assertOrderedDataInValidatorCache(final boolean cacheEntryExpired) {
        final ValidatorCache validatorCache = ValidatorCache.INSTANCE;
        assertEquals("Expected cache map [" + VALIDATOR_NAMES.length + "].", VALIDATOR_NAMES.length, validatorCache.getNameToIdMap().entrySet().size());
        for(int index = 0; index < VALIDATOR_NAMES.length; index++) {
            assertValidatorCacheEntry(index, VALIDATOR_NAMES[index], VALIDATORS[index], cacheEntryExpired);
        }
    }

    private void assertValidatorCacheEntry(
            final int cacheId,
            final String validatorName, final ValidatorBase validator,
            final boolean cacheEntryExpired
    ) {
        final ValidatorCache validatorCache = ValidatorCache.INSTANCE;
        assertEquals(
                "Wrong mapping by name for name [" + validatorName + "] with id [" + cacheId + "]",
                cacheId,
                validatorCache.getNameToIdMap().get(validatorName).intValue()
        );
        assertEquals(
                "Expected cache to return same instance of object [" + validator + "].",
                validator,
                validatorCache.getEntry(cacheId)
        );
        assertEquals(
                "Cache indicated that existing object with id [" + cacheId + "] is " + (cacheEntryExpired ? "valid" : "invalid"),
                cacheEntryExpired,
                validatorCache.shouldCheckForUpdates(cacheId)
        );
        assertEquals(
                "Wrong mapping by id for name [" + validatorName + "] with id [" + cacheId + "]",
                validatorName,
                validatorCache.getName(cacheId)
        );
    }
}
