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
package org.cesecore.junit.util;

import org.apache.log4j.Logger;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RetryRuleUnitTest {

    private static final Logger log = Logger.getLogger(RetryRuleUnitTest.class);

    private static int attemptCounter = 0;
    private final int retryCount = 3;

    @Rule
    public TestRule retryRule = new RetryRule(retryCount);

    @Test
    public void shouldRetryFailedTestsAGivenNumberOfTimes () {
        attemptCounter++;
        log.info("Attempt #" + attemptCounter + " for testRetryMechanism...");

        // simulate test failure for the first two attempts
        if (attemptCounter < retryCount) {
            fail("Simulated test failure");
        }

        if (attemptCounter > retryCount) {
            fail("Test failed after " + retryCount + " attempts which is greater than the configured retry count of " + retryCount);
        }

        // ensure the test passes on the 3rd attempt
        assertTrue("The test should have passed after " + (retryCount - 1) + " retries", true);
    }
}