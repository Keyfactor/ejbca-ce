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
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

public class RetryRule implements TestRule {

    private static final Logger log = Logger.getLogger(RetryRule.class);

    private final int retryCount;
    private final long delayBetweenRetriesMs;

    /**
     * Constructor for RetryRule with retry count and a delay between retries.
     *
     * @param retryCount  The number of retry attempts.
     * @param delayBetweenRetriesMs The delay in milliseconds between retries.
     */
    public RetryRule(int retryCount, long delayBetweenRetriesMs) {
        this.retryCount = retryCount;
        this.delayBetweenRetriesMs = delayBetweenRetriesMs;
    }

    /**
     * Constructor for RetryRule without delay (default behavior).
     *
     * @param retryCount The number of retry attempts.
     */
    public RetryRule(int retryCount) {
        this(retryCount, 0);
    }

    @Override
    public Statement apply(Statement base, Description description) {
        return new RetryStatement(base, retryCount, delayBetweenRetriesMs);
    }

    private static class RetryStatement extends Statement {
        private final Statement base;
        private final int retryCount;
        private final long delayBetweenRetriesMs;

        RetryStatement(Statement base, int retryCount, long delayBetweenRetriesMs) {
            this.base = base;
            this.retryCount = retryCount;
            this.delayBetweenRetriesMs = delayBetweenRetriesMs;
        }

        @Override
        @SuppressWarnings("squid:S2925") // suppresses the "Thread.sleep()" warning
        public void evaluate() throws Throwable {
            Throwable lastThrowable = null;
            for (int i = 0; i < retryCount; i++) {
                try {
                    base.evaluate(); // attempt to run the test
                    return; // test passed successfully, no need to retry further
                } catch (Throwable t) {
                    lastThrowable = t;
                    log.error("Test failed on attempt " + (i + 1) + ": " + t.getMessage());

                    // apply a delay between retries if specified
                    if (i < retryCount - 1 && delayBetweenRetriesMs > 0) {
                        try {
                            Thread.sleep(delayBetweenRetriesMs);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt(); // preserve the interrupted status
                            throw e; // rethrow if interrupted
                        }
                    }
                }
            }
            log.error("Test failed after " + retryCount + " attempts.");
            assert lastThrowable != null;
            throw lastThrowable; // throw the last exception if all retries fail
        }
    }
}