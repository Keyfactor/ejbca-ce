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
package org.ejbca.core.model.validation.domainblacklist;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.profiles.ProfileData;
import org.ejbca.core.model.validation.DomainBlacklistValidator;
import org.junit.Test;

/**
 * Tests that the transient cache field in {@link DomainBlacklistValidator} is correctly initialized after deserialization (and before putting into cache)
 * 
 * @version $Id$
 */
public class DomainBlacklistCacheUnitTest {

    private static final Logger log = Logger.getLogger(DomainBlacklistCacheUnitTest.class);

    /** Checks that the transient internal cache in DomainBlacklistValidators is built even in validators from the validator cache. */
    @Test
    public void transientFieldInitialization() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
        // given
        final String validatorName = "testValidatorTransientCaching";
        final int validatorId = 54321;
        final Date validatorUpdateDate = new Date();
        final String validatorBlacklistHash = "abcdef123456";
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        validator.setProfileName(validatorName);
        validator.setDescription("foobar");
        validator.setBlacklist(new ArrayList<>(Collections.singleton("cachetesting.example.net")));
        validator.setBlacklistDate(validatorUpdateDate);
        validator.setBlacklistSha256(validatorBlacklistHash);
        validator.setChecks(new ArrayList<>(Collections.singleton(DomainBlacklistExactMatchChecker.class.getName())));
        validator.setFailedAction(KeyValidationFailedActions.LOG_INFO.getIndex());
        // when
        final ProfileData serialized = new ProfileData(validatorId, validator);
        final DomainBlacklistValidator deserializedValidator = (DomainBlacklistValidator) serialized.getProfile();
        // then
        final Field cacheField = DomainBlacklistValidator.class.getDeclaredField("cache");
        cacheField.setAccessible(true);
        final Object internalCache = cacheField.get(deserializedValidator);
        assertNotNull("Cache should have been initialized", internalCache); // must be checked first, to avoid lazy-initialization
        assertEquals("Description is not what we set", "foobar", deserializedValidator.getDescription());
        assertEquals("Domain validator blacklist hash is wrong.", validatorBlacklistHash, deserializedValidator.getBlacklistSha256());
        assertEquals("Domain validator blacklist update date is wrong.", validatorUpdateDate, deserializedValidator.getBlacklistDate());
        assertFalse("Domain should be in blacklist" , deserializedValidator.validate(null, "cachetesting.example.net").getKey());
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
    }
}
