/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Tests DomainBlacklistExactMatchChecker functions.
 *
 * @version $Id$
 */
public class DomainBlacklistExactMatchCheckerTest {

    @Test(expected = IllegalStateException.class)
    public void checkNotInitialized() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        checker.check("something");
    }

    @Test
    public void checkNotInBlackList() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        checker.initialize(null, Collections.emptySet());
        boolean result = checker.check("something");
        assertTrue("Domain should be accepted", result);
    }

    @Test
    public void checkInBlackList() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("something.com");
        assertFalse("Domain should not be accepted", result);
    }

    @Test
    public void checkPartInBlackList() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("something.com");
        assertTrue("Domain should be accepted", result);
    }

}