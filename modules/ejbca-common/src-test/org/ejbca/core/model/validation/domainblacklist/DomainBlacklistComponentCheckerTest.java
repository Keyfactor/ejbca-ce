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

import java.util.Collections;
import java.util.Map;

import org.cesecore.util.MapTools;
import org.junit.Test;

/**
 * Tests DomainBlacklistComponentChecker functions.
 * @version $Id$
 */
public class DomainBlacklistComponentCheckerTest {

    private static final Map<String,String> BLACKLIST = MapTools.unmodifiableMap(
            "something.com", "somethingORIG.com", // normalized -> original, un-normalized, domain
            "bank", "bankORIG",
            "paypal.com", "paypalORIG.com"
            );

    @Test(expected = IllegalStateException.class)
    public void checkNotInitialized() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.check("something");
    }

    @Test
    public void checkEmptyBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, Collections.emptyMap());
        final String result = checker.check("something");
        assertNull("'something' domain should be accepted by Component checker", result);
    }

    @Test
    public void checkPartInBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("bank.com");
        assertEquals("'bank.com' domain should not be accepted by Component checker", "bankORIG", result);
    }

    @Test
    public void checkInMiddlePartBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("test.bank.com");
        assertEquals("'test.bank.com' domain should not be accepted  by Component checker", "bankORIG", result);
    }

    @Test
    public void checkWordPartInBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("memorybank.com");
        assertNull("'memorybank.com' domain should be accepted by Component checker", result);
    }

    @Test
    public void checkFullDomainBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("paypal.com");
        assertNull("'paypal.com' domain should be accepted by Component checker", result);
    }

    @Test
    public void checkDomainPartWithDotInBlackList() throws Exception {
        DomainBlacklistComponentChecker checker = new DomainBlacklistComponentChecker();
        checker.initialize(null, BLACKLIST);
        final String result = checker.check("login.paypal.com");
        assertNull("'login.paypal.com' domain should be accepted by Component checker", result);
    }

}