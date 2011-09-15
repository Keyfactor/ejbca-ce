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

package org.ejbca.appserver.jboss;

import java.util.Date;

import org.apache.log4j.spi.LoggingEvent;

/**
 * The purpose of this errorhandler is that we can still respond with InternalServer error if and error occurs,
 * but repeated errors will only be logged once.
 * 
 * @author Tham Wickenberg
 * @version  $Id$
 */

public class ProbeableErrorHandler extends org.jboss.logging.util.OnlyOnceErrorHandler {
	private static Date lastFailure = null;
	
	public void error(String arg0) {
		super.error( arg0);
		lastFailure = new Date();
	}

	public void error(String arg0, Exception arg1, int arg2) {
		super.error(arg0, arg1, arg2);
		lastFailure = new Date();
	}

	public void error(String arg0, Exception arg1, int arg2, LoggingEvent arg3) {
		super.error(arg0, arg1, arg2, arg3);
		lastFailure = new Date();
	}

	/** Returns true if an error writing to the log files have happened since 'date'.
	 *  
	 * @param date see if an error happened later than this date 
	 * @return true if an error has happened, false if logging works fine.
	 */
	public static boolean hasFailedSince(Date date) {
		if (lastFailure != null) {
			if(lastFailure.after(date) ) {
				return true;
			}
		}
		return false;
	}

}
