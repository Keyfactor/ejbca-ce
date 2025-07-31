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

public class RetryRuleWithDelayUnitTest {

    private static final long TEST_START_TIME_MS = System.currentTimeMillis();
    private static final Logger log = Logger.getLogger(RetryRuleWithDelayUnitTest.class);

    private static int attemptCounter = 0;
    private final int retryCount = 3;
    private final int delayInMilliseconds = 100;

    @Rule
    public TestRule retryRule = new RetryRule(retryCount, delayInMilliseconds);


    @Test
    public void shouldRetryTestsWithDelay() {
        attemptCounter++;
        log.info("Attempt #" + attemptCounter + " for test with delay...");

        // simulate test failure for the two attempts
        if (attemptCounter < retryCount) {
            fail("Simulated test failure");
        }

        final long elapsedTimeMs = System.currentTimeMillis() - TEST_START_TIME_MS;
        final long expectedMinimumRuntimeMs = delayInMilliseconds * (retryCount - 1);

        // Time-sensitive tests can be flaky, so as long as the test doesn't take longer than X seconds to finish, we're good.
        final int leewayMs = 1000;
        final long maxRuntime = expectedMinimumRuntimeMs + leewayMs;


        assertTrue("The test should have passed after " + (retryCount - 1) + " retries", true);
        assertTrue("Expected minimum retry delay of " + expectedMinimumRuntimeMs + "ms, but was " + elapsedTimeMs + "ms", elapsedTimeMs >= expectedMinimumRuntimeMs);
        assertTrue("Expected maximum runtime (retry delay sum) of " + maxRuntime + "ms, but was " + elapsedTimeMs + "ms", elapsedTimeMs <= maxRuntime);
    }
}