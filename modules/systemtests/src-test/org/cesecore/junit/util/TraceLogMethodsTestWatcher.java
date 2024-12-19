/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * The test watcher logs the name of the methods executed as tests ([at]Test) on trace level.
 * 
 * Starting: >methodName
 * Finished: <methodName
 */
public class TraceLogMethodsTestWatcher extends TestWatcher {

    private Logger log;

    public TraceLogMethodsTestWatcher(final Logger log) {
        this.log = log;
    }

    @Override
    protected void starting(final Description description) {
        log.trace(">" + description.getMethodName());
        super.starting(description);
    };

    @Override
    protected void finished(final Description description) {
        log.trace("<" + description.getMethodName());
        super.finished(description);
    }
}
