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
package org.ejbca.core.ejb;

import java.util.Arrays;

import javax.interceptor.AroundInvoke;
import javax.interceptor.InvocationContext;

import org.apache.log4j.Logger;

/**
 * EJB Interceptor that is normally enabled for all EJBs when EJBCA is running in non-production mode.
 * 
 * The Interceptor will perform two tasks when active:
 * - Trace log all EJB invocations including input and output if Log4J trace-logging is enabled for the invoked methods EJB.
 * - Collect profiling statistics for all EJB invocations if Log4J debug is enabled for this class.
 * 
 * @version $Id$
 */
public class ProfileAndTraceInterceptor {

    private static final Logger log = Logger.getLogger(ProfileAndTraceInterceptor.class);
    
    @AroundInvoke
    public Object logger(final InvocationContext invocationContext) throws Exception {
        if (!log.isDebugEnabled()) {
            return invocationContext.proceed();
        }
        long invocationStartTime = 0;
        final String targetMethodName = invocationContext.getMethod().getName();
        final Class<?> targetMethodClass = invocationContext.getTarget().getClass();
        final Logger targetLogger = Logger.getLogger(targetMethodClass);
        invocationStartTime = System.nanoTime();
        if (targetLogger.isTraceEnabled()) {
            targetLogger.trace(">" + targetMethodName + "(" + Arrays.toString(invocationContext.getParameters()) + ")");
        }
        Object returnValue = null;
        Exception returnException = null; 
        try {
            returnValue = invocationContext.proceed();
        } catch (Exception e) {
            returnException = e;
            throw e;
        } finally {
            long invocationDuration = -1;
            invocationDuration = (System.nanoTime() - invocationStartTime) / 1000;
            final String fullTargetIdentifier = targetMethodClass.getName() + "." + targetMethodName;
            ProfilingStats.INSTANCE.add(fullTargetIdentifier, invocationDuration);
            if (targetLogger.isTraceEnabled()) {
                if (returnException == null) {
                    targetLogger.trace("<" + targetMethodName + " took " + invocationDuration + "micros");
                } else {
                    targetLogger.trace("<" + targetMethodName + " took " + invocationDuration + "micros, threw " + returnException.getClass().getName() + ": " + returnException.getMessage());
                }
            }
        }
        return returnValue;
    }
}
