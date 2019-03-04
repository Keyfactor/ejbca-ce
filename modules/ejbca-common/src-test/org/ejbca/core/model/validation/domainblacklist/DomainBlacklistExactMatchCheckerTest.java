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
 * Tests DomainBlacklistExactMatchChecker functions.
 *
 * @version $Id$
 */
public class DomainBlacklistExactMatchCheckerTest {

    private static final Map<String,String> BLACKLIST1 = MapTools.unmodifiableMap(
            "something.com", "somethingORIG.com", // normalized -> original, un-normalized, domain
            "bank", "bankORIG",
            "paypal.com", "paypalORIG.com"
            );

    private static final Map<String,String> BLACKLIST2 = MapTools.unmodifiableMap(
            "something", "somethingORIG", // normalized -> original, un-normalized, domain
            "bank", "bankORIG",
            "paypal.com", "paypalORIG.com"
            );

    @Test(expected = IllegalStateException.class)
    public void checkNotInitialized() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        checker.check("something");
    }

    @Test
    public void checkEmptyBlackList() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        checker.initialize(null, Collections.emptyMap());
        final String result = checker.check("something");
        assertNull("'something' domain should be accepted by Exact Match checker", result);
    }

    @Test
    public void checkInBlackList() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        checker.initialize(null, BLACKLIST1);
        final String result = checker.check("something.com");
        assertEquals("'something.com' domain should not be accepted by Exact Match checker", "somethingORIG.com", result);
    }

    @Test
    public void checkPartInBlackList() throws Exception {
        DomainBlacklistExactMatchChecker checker = new DomainBlacklistExactMatchChecker();
        checker.initialize(null, BLACKLIST2);
        final String result = checker.check("something.com");
        assertNull("'something.com' domain should be accepted by Exact Match checker", result);
    }

}