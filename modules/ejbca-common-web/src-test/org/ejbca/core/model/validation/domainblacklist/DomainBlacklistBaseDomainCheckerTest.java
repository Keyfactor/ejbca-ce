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
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Tests DomainBlacklistBaseDomainChecker functions.
 * @version $Id$
 */
public class DomainBlacklistBaseDomainCheckerTest {

    @Test(expected = IllegalStateException.class)
    public void checkNotInitialized() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.check("something");
    }

    @Test
    public void checkPartInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("bank.com");
        assertTrue("'bank.com' domain should be accepted by Base Domain checker", result);
    }

    @Test
    public void checkInMiddlePartBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("test.bank.com");
        assertTrue("'test.bank.com' domain should be accepted by Base Domain checker", result);
    }

    @Test
    public void checkWordPartInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("memorybank.com");
        assertTrue("'memorybank.com' domain should be accepted by Base Domain checker", result);
    }

    @Test
    public void checkFullDomainBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("paypal.com");
        assertFalse("'paypal.com' domain should be not accepted by Base Domain checker", result);
    }

    @Test
    public void checkDomainPartWithDotInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("login.paypal.com");
        assertFalse("'login.paypal.com' domain should not be accepted by Base Domain checker", result);
    }

    @Test
    public void checkDomainWithDifferentBaseInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("paypal.org");
        assertTrue("'login.paypal.com' domain should be accepted by Base Domain checker", result);
    }

}