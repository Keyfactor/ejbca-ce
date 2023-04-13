/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.util.log;

import java.io.PrintStream;
import java.util.Date;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

/**
 * The purpose of this errorhandler is that we can still respond with InternalServer error if and error occurs, but repeated errors will only be
 * logged once.
 * 
 * @version $Id$
 */

public class ProbableErrorHandler implements ErrorHandler {
    private static Date lastFailure = null;

    final String WARN_PREFIX = "log4j warning: ";
    final String ERROR_PREFIX = "log4j error: ";

    boolean firstTime = true;

    static PrintStream output = System.err;
    
    @Override
    public void error(String arg0) {
        if (firstTime) {
            output.println(ERROR_PREFIX + arg0);
            firstTime = false;
        }
        lastFailure = new Date();
    }

    @Override
    public void error(String arg0, Exception arg1, int arg2) {
        error(arg0, arg1, arg2, null);
        lastFailure = new Date();
    }

    @Override
    public void error(String arg0, Exception arg1, int arg2, LoggingEvent arg3) {
        if (firstTime) {
            output.println(ERROR_PREFIX + arg0);
            arg1.printStackTrace(output);
            firstTime = false;
        }
        lastFailure = new Date();
    }

    /**
     * Returns true if an error writing to the log files have happened since 'date'.
     * 
     * @param date see if an error happened later than this date
     * @return true if an error has happened, false if logging works fine.
     */
    public static boolean hasFailedSince(Date date) {
        if (lastFailure != null) {
            if (lastFailure.after(date)) {
                return true;
            }
        }
        return false;
    }

    /** Does not do anything. */
    @Override
    public void setLogger(Logger logger) {
    }
    
    /** Does not do anything. */
    @Override
    public void setAppender(Appender appender) {
    }

    /** Does not do anything. */
    @Override
    public void setBackupAppender(Appender appender) {
    }
}
