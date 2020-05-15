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
package org.ejbca.webtest.junit;

import org.junit.runner.Result;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

/**
 * An implementation of a runner for JUnit tests that allows to track RAM memory consumption registering the tests
 * execution listener (MemoryTrackingRunListener). This listener traces the RAM usage through the test run lifecycle.
 * <br/>
 * To enable memory tracing annotate your test class with @RunWith(MemoryTrackingTestRunner.class), eg.:
 * <pre>
 * &#64;RunWith(MemoryTrackingTestRunner.class)
 * public class MyUnitTest {
 *
 *     &#64;Test
 *     public void shouldHeavilyUseMemory {
 *         // Test body
 *     }
 * }
 * </pre>
 * <br/>
 * Check corresponding logs for memory trace.
 *
 * @see org.junit.runners.BlockJUnit4ClassRunner
 * @see MemoryTrackingRunListener
 * @see org.ejbca.webtest.util.RuntimeUtil
 *
 * @version $Id: MemoryTrackingTestRunner.java 34938 2020-04-28 14:58:22Z andrey_s_helmes $
 */
public class MemoryTrackingTestRunner extends BlockJUnit4ClassRunner {

    /**
     * Default constructor.
     * @param clazz class.
     * @throws InitializationError in case of initialization error of a Runner.
     */
    public MemoryTrackingTestRunner(final Class<?> clazz) throws InitializationError {
        super(clazz);
    }

    /**
     * Adds the listener MemoryTrackingRunListener.
     * @param runNotifier run notifier.
     */
    @Override
    public void run(final RunNotifier runNotifier){
        runNotifier.addListener(new MemoryTrackingRunListener());
        runNotifier.fireTestRunStarted(getDescription());
        super.run(runNotifier);
        // Workaround to trigger testRunFinished in attached listener for ant
        // https://bz.apache.org/bugzilla/show_bug.cgi?id=54970
        runNotifier.fireTestRunFinished(new Result());
    }
}
