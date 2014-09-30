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
package org.cesecore.util;

import org.apache.log4j.Logger;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * By adding this TestRule to your test class, all methods will have a start and end trace logging.
 * 
 * <code>
 * @org.junit.Rule
 * public org.junit.rules.TestRule traceLogMethodsRule = new TraceLogMethodsRule();
 * </code>
 *  
 * @version $Id$
 */
public class TraceLogMethodsRule extends TestWatcher {

    @Override
    protected void starting(Description description) {
        final Logger log = Logger.getLogger(description.getClassName());
        if (log.isTraceEnabled()) {
            log.trace(">" + description.getMethodName());
        }
        super.starting(description);
    };

    @Override
    protected void finished(Description description) {
        final Logger log = Logger.getLogger(description.getClassName());
        if (log.isTraceEnabled()) {
            log.trace("<" + description.getMethodName());
        }
        super.finished(description);
    }
}
