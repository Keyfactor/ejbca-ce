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

import org.ejbca.webtest.util.RuntimeUtil;
import org.junit.runner.Description;
import org.junit.runner.Result;
import org.junit.runner.notification.RunListener;

/**
 * This class listens for JUnit events:
 * <ul>
 *     <li>testRunStarted - Called before any tests have been run.</li>
 *     <li>testRunFinished - Called when all tests have finished.</li>
 *     <li>testStarted - Called when an atomic test is about to be started.</li>
 *     <li>testFinished - Called when an atomic test has finished, whether the test succeeds or fails.</li>
 * </ul>
 * Per each event this listener call RuntimeUtil to output the RAM memory state.
 *
 * @see RuntimeUtil#outputRuntimeRAMDetails()
 *
 * @version $Id: MemoryTrackingTestRunner.java 34938 2020-04-28 14:58:22Z andrey_s_helmes $
 */
public class MemoryTrackingRunListener extends RunListener {

    /**
     * Called before any tests have been run.
     * @param description describes the tests to be run
     */
    public void testRunStarted(final Description description) {
        System.out.println("" + description.getClassName() + " number of tests: " + description.testCount());
        RuntimeUtil.outputRuntimeRAMDetails();
    }

    /**
     * Called when all tests have finished.
     * @param result the summary of the test run, including all the tests that failed
     */
    public void testRunFinished(final Result result) {
        System.out.println("Number of executed tests: " + result.getRunCount());
        RuntimeUtil.outputRuntimeRAMDetails();
    }

    /**
     * Called when an atomic test is about to be started.
     * @param description the description of the test that is about to be run
     * (generally a class and method name).
     */
    public void testStarted(final Description description) {
        System.out.println("Executing " + description.getClassName() + "." + description.getMethodName() + "...");
        RuntimeUtil.outputRuntimeRAMDetails();
    }

    /**
     * Called when an atomic test has finished, whether the test succeeds or fails.
     * @param description the description of the test that just ran
     */
    public void testFinished(final Description description) {
        System.out.println("Executed " + description.getDisplayName() + description.getClassName() + "." + description.getMethodName() + ".");
        RuntimeUtil.outputRuntimeRAMDetails();
    }
}
