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
 *
 * @version $Id$
 */
public class DomainBlacklistComponentCheckerTest {


    @Test(expected = IllegalStateException.class)
    public void checkNotInitialized() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.check("something");
    }

    @Test
    public void checkEmptyBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, Collections.emptySet());
        boolean result = checker.check("something");
        assertTrue("'something' domain should be accepted by Component checker", result);
    }

    @Test
    public void checkPartInBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("bank.com");
        assertFalse("'bank.com' domain should not be accepted by Component checker", result);
    }

    @Test
    public void checkInMiddlePartBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("test.bank.com");
        assertFalse("'test.bank.com' domain should not be accepted  by Component checker", result);
    }

    @Test
    public void checkWordPartInBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("memorybank.com");
        assertTrue("'memorybank.com' domain should be accepted by Component checker", result);
    }

    @Test
    public void checkFullDomainBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("paypal.com");
        assertTrue("'paypal.com' domain should be accepted by Component checker", result);
    }

    @Test
    public void checkDomainPartWithDotInBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        Set<String> blacklist = new HashSet<>(Arrays.asList("something.com", "bank", "paypal.com"));
        checker.initialize(null, blacklist);
        boolean result = checker.check("login.paypal.com");
        assertTrue("'login.paypal.com' domain should be accepted by Component checker", result);
    }

}