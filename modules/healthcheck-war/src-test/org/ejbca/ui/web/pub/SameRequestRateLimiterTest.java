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
package org.ejbca.ui.web.pub;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;

/**
 * Test code for util class that allows many concurrent requests for the same thing to share the result.
 * 
 * @version $Id$
 */
public class SameRequestRateLimiterTest {
    
    private static final Logger log = Logger.getLogger(SameRequestRateLimiterTest.class);

    private int nextValue = 0;
    SameRequestRateLimiter<Integer> srrl = null;
    
    @Before
    public void setUp() {
        nextValue = 0;
        srrl = new SameRequestRateLimiter<Integer>();
    }

    @Test
    public void test100ThreadsWithoutLimiter() throws Exception {
        log.trace(">test100ThreadsWithoutLimiter");
        final List<Integer> allResults = new ArrayList<Integer>();
        // Start a 100 threads that perform want to perform the same request concurrently
        startTasks(allResults, 100, false);
        waitForAllResults(allResults, 100, 10);
        assertEquals("Incorrect nextValue. Request method was invoked less than 100 times!", 100, nextValue);
        // Verify that we have 100 unique invocations without the rate limiter
        for (final Integer resultValue : allResults) {
            boolean once = false;
            for (final Integer resultValue2 : allResults) {
                if (resultValue.intValue() == resultValue2.intValue()) {
                    assertFalse("Result occurred twice! We expect unique invocations..", once);
                    once = true;
                }
            }
        }
        log.trace("<test100ThreadsWithoutLimiter");
    }

    @Test
    public void test100ThreadsWithLimiter() {
        log.trace(">test100ThreadsWithLimiter");
        final List<Integer> allResults = new ArrayList<Integer>();
        // Start a 100 threads that perform want to perform the same request concurrently
        startTasks(allResults, 100, true);
        waitForAllResults(allResults, 100, 10);
        assertEquals("Incorrect nextValue. Request method was invoked more than one time!", 1, nextValue);
        // Verify that we have 1 unique invocations with the rate limiter
        for (Integer resultValue : allResults) {
            assertEquals("Incorrect result returned! All threads should get the same expected result value.", 0, resultValue.intValue());
        }
        log.trace("<test100ThreadsWithLimiter");
    }

    /** Start threads that perform the task */
    private void startTasks(final List<Integer> allResults, final int threads, final boolean useLimitWrapper) {
        log.trace(">startTasks");
        for (int i=0; i<threads; i++) {
            new Thread() {
                @Override
                public void run() {
                    final Integer resultValue;
                    if (useLimitWrapper) {
                        resultValue = getNextValueLimitWrapper();
                    } else {
                        resultValue = getNextValue();
                    }
                    synchronized (allResults) {
                        allResults.add(resultValue);
                    }
                    super.run();
                }
            }.start();
        }
        log.trace("<startTasks");
    }

    /** Wait up to "timeoutSeconds" seconds for all "expected" number of threads to complete.. */
    private void waitForAllResults(final List<Integer> allResults, int expected, int timeoutSeconds) {
        log.trace(">waitForAllResults");
        while (timeoutSeconds-->0) {
            synchronized (allResults) {
                if (allResults.size()>=expected) {
                    break;
                }
            }
            log.info("Waiting another second for all tasks to complete..");
            sleep(1000L);
        }
        log.trace("<waitForAllResults");
    }
    
    /** Wrapped task */
    private Integer getNextValueLimitWrapper() {
        log.trace(">getNextValueLimitWrapper");
        final SameRequestRateLimiter<Integer>.Result result = srrl.getResult();
        if (result.isFirst()) {
            try {
                // Perform common action
                final Integer value = Integer.valueOf(getNextValue());
                result.setValue(value);
            } catch (Throwable t) { // NOPMD: we want to catch all possible strangeness
                result.setError(t);
            }
        }
        log.trace("<getNextValueLimitWrapper");
        return result.getValue();
    }

    /** Original task emulation */
    private Integer getNextValue() {
        log.trace(">getNextValue");
        // What the util really does is save server load when the same result is returned, but we need to increase the counter to track invocations..
        final Integer ret;
        synchronized (SameRequestRateLimiterTest.this) {
            ret = Integer.valueOf(nextValue++);
        }
        log.info("Pretending to be tasks that generates server load.. Current invocation: " + ret);
        sleep(1000L);
        log.trace("<getNextValue");
        return ret;
    }
    
    /** Simple Thread.sleep wrapper */
    private void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
