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
package org.cesecore.audit.impl.log4j;

import org.apache.logging.log4j.core.ErrorHandler;
import org.apache.logging.log4j.core.LogEvent;

/**
 * Custom wrapper for Log4J ErrorHandler, so we can check if logging was successful or not.
 * 
 * @version $Id$
 */
public class Log4jDeviceErrorHandler implements ErrorHandler {
	
	private boolean ok = true;
	
	private final ErrorHandler errorHandler;
	
	public Log4jDeviceErrorHandler(final ErrorHandler errorHandler) {
		this.errorHandler = errorHandler;
	}
	
	/** @return true if this error handler has not been invoked since last call to this method. */
	public boolean isOk() {
		if (ok) {
			return true;
		}
		ok = true;	// Reset
		return false;
	}

	@Override
	public void error(final String arg0) {
		errorHandler.error(arg0);
		ok = false;
	}

	// ECA-10518 No fix required?
//	@Override
//	public void setAppender(final Appender arg0) {
//		errorHandler.setAppender(arg0);
//	}
//
//	@Override
//	public void setBackupAppender(final Appender arg0) {
//		errorHandler.setBackupAppender(arg0);
//	}
//
//	@Override
//	public void setLogger(final Logger arg0) {
//		errorHandler.setLogger(arg0);
//	}

	@Override
    public void error(String msg, Throwable t) {
        errorHandler.error(msg, t);
        ok = false;
        
    }

    @Override
    public void error(String msg, LogEvent event, Throwable t) {
        errorHandler.error(msg, event, t);
        ok = false;        
    }

}
