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
package org.ejbca.core.model.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.ejbca.core.model.validation.domainblacklist.DomainBlacklistAsciiLookalikeNormalizer;
import org.ejbca.core.model.validation.domainblacklist.DomainBlacklistBaseDomainChecker;
import org.junit.Test;

/**
 * Unit test of DomainBlacklistValidator
 *
 * @version $Id$
 */
public class DomainBlacklistValidatorUnitTest {

    private static final Logger log = Logger.getLogger(DomainBlacklistValidatorUnitTest.class);

    private static final byte[] BLACKLIST = ("bank\n" + 
            "forbidden.example.com\n" + 
            "#good.example.com\n" + 
            "forbidden2.example.com # this is a comment\n" + 
            "    forbidden3.example.com     \n" + 
            "forbidden4.example.com# comment\n" + 
            "\n").getBytes(StandardCharsets.UTF_8);
    private static final String BLACKLIST_SHA256 = "c7a7015f58dd0dd4fb7021b8e93760aa2614d08df1b6e1676a1c1660957e47db";

    private static final byte[] MALFORMED_BLACKLIST = ("# some line\n" + 
            "detta-behöver-punycodas\n" + // line that is not punycoded
            "\n").getBytes(StandardCharsets.UTF_8);

    @Test
    public void parseBlacklistFile() {
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        validator.changeBlacklist(BLACKLIST);
        final Collection<String> blacklist = validator.getBlacklist();
        log.debug("Result after parsing: " + blacklist);
        assertEquals("Wrong number of entries in parsed blacklist.", 5, blacklist.size());
        assertTrue("Should contain 'forbidden.example.com'", blacklist.contains("forbidden.example.com"));
        assertTrue("Should contain 'forbidden2.example.com'", blacklist.contains("forbidden2.example.com"));
        assertTrue("Should contain 'forbidden3.example.com'", blacklist.contains("forbidden3.example.com"));
        assertTrue("Should contain 'forbidden4.example.com'", blacklist.contains("forbidden4.example.com"));
        assertEquals("Wrong SHA-256 hash.", BLACKLIST_SHA256, validator.getBlacklistSha256());
        assertNotNull("Upload date should be set", validator.getBlacklistDate());
    }

    @Test
    public void parseMalformedBlacklistFile() {
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        try {
            validator.changeBlacklist(MALFORMED_BLACKLIST);
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("Invalid syntax of domain at line 2."));
        }
    }

    @Test
    public void matchAllowedAgainstBlacklist() {
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        validator.changeBlacklist(BLACKLIST);
        validator.setNormalizations(Arrays.asList(DomainBlacklistAsciiLookalikeNormalizer.class.getName()));
        validator.setChecks(Arrays.asList(DomainBlacklistBaseDomainChecker.class.getName()));
        // These are allowed
        tryValidator(validator, "allowed.example.com", true);
        tryValidator(validator, "forbidden.example.com.example.net", true);
    }

    @Test
    public void matchBlockedAgainstBlacklist() {
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        validator.changeBlacklist(BLACKLIST);
        validator.setNormalizations(Arrays.asList(DomainBlacklistAsciiLookalikeNormalizer.class.getName()));
        validator.setChecks(Arrays.asList(DomainBlacklistBaseDomainChecker.class.getName()));
        // This is not allowed
        tryValidator(validator, "subdomain.forbidden.example.com", false);
        tryValidator(validator, "subdomain.f0rbiclclen.example.com", false);
    }

    private void tryValidator(final DomainBlacklistValidator validator, final String domain, final boolean expectedResult) {
        final Entry<Boolean,List<String>> result = validator.validate(null, domain);
        assertEquals("Unexpected validator result for " + domain + ". ",  expectedResult, result.getKey());
    }

    /** Checks that the exception message contains both the requested and the blacklisted domain. */
    @Test
    public void checkExceptionMessage() {
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        validator.changeBlacklist(BLACKLIST);
        validator.setNormalizations(Arrays.asList(DomainBlacklistAsciiLookalikeNormalizer.class.getName()));
        validator.setChecks(Arrays.asList(DomainBlacklistBaseDomainChecker.class.getName()));
        validator.setFailedAction(KeyValidationFailedActions.LOG_INFO.getIndex());
        final Entry<Boolean,List<String>> result = validator.validate(null, "f0rbiclclen2.example.com");
        assertFalse("Domain should be blacklsted", result.getKey());
        final String expectedMessage = "Domain 'f0rbiclclen2.example.com' is blacklisted. Matching domain on blacklist: 'forbidden2.example.com'";
        assertEquals("Wrong exception message.", expectedMessage, result.getValue().get(0));
    }
}
