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

package org.ejbca.core.protocol.ocsp;

import java.util.Date;

import org.apache.log4j.spi.LoggingEvent;

/**
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
	
	public static boolean hasFailedSince(Date date) {
		if (lastFailure != null) {
			if(lastFailure.after(date) ) {
				return true;
			}
		} else {
		}
		return false;
	}

}
