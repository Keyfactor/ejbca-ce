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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Map;

import org.cesecore.util.MapTools;
import org.junit.Test;

/**
 * Tests DomainBlacklistBaseDomainChecker functions.
 * @version $Id$
 */
public class DomainBlacklistBaseDomainCheckerTest {

    private static final Map<String,String> BLACKLIST = MapTools.unmodifiableMap(
            "something.com", "somethingORIG.com", // normalized -> original, un-normalized, domain
            "bank", "bankORIG",
            "paypal.com", "paypalORIG.com"
            );

    @Test(expected = IllegalStateException.class)
    public void checkNotInitialized() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.check("something");
    }

    @Test
    public void checkPartInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("bank.com");
        assertNull("'bank.com' domain should be accepted by Base Domain checker", result);
    }

    @Test
    public void checkInMiddlePartBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("test.bank.com");
        assertNull("'test.bank.com' domain should be accepted by Base Domain checker", result);
    }

    @Test
    public void checkWordPartInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("memorybank.com");
        assertNull("'memorybank.com' domain should be accepted by Base Domain checker", result);
    }

    @Test
    public void checkFullDomainBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("paypal.com");
        assertEquals("'paypal.com' domain should be not accepted by Base Domain checker", "paypalORIG.com", result);
    }

    @Test
    public void checkDomainPartWithDotInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("login.paypal.com");
        assertEquals("'login.paypal.com' domain should not be accepted by Base Domain checker", "paypalORIG.com", result);
    }

    @Test
    public void checkDomainWithDifferentBaseInBlackList() throws Exception {
        DomainBlacklistBaseDomainChecker checker = new DomainBlacklistBaseDomainChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("paypal.org");
        assertNull("'login.paypal.com' domain should be accepted by Base Domain checker", result);
    }

}