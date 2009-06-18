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

import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.ejbca.util.GUIDGenerator;
import org.ejbca.util.PatternLogger;

/**
 * This class is used for logging ocsp-responses with the purpose of auditing.
 * It can be used to store entire ocsp-requests and responses which means the log can be used to verify requests afterwards.
 * 
 * @author tham
 * @version $Id$
 */
public class AuditLogger extends PatternLogger implements IAuditLogger { 
	private static Pattern PATTERN;
	private static String orderString;
    private static final Logger accountLog = Logger.getLogger(AuditLogger.class.getName());
	private static String mLogDateFormat ;
	private static String mTimeZone;
	
	//TRY_LATER = 3;SIG_REQUIRED = 5;UNAUTHORIZED = 6;
	 /** regexp pattern to match ${identifier} patterns */// ${DN};${IP}

	public AuditLogger () {
		super(PATTERN.matcher(orderString), orderString, accountLog, mLogDateFormat, mTimeZone);
		cleanParams();
        //super.paramPut(LOG_TIME, new Date().toString());
	}
	
	/**
	 * Use this method to avoid having parts of the order-string logged when some values have not been stored before a writeln()
	 */
	protected void cleanParams() {
		super.cleanParams();
		super.paramPut(CLIENT_IP,"0");
		super.paramPut(OCSPREQUEST, "0");
		super.paramPut(OCSPRESPONSE, "0");
		super.paramPut(STATUS, "-1");
	}
	
	/**
	 * This Method needs to be called before creating any instances
	 * 
	 * @param accountLogPattern  
	 * @param accountLogOrder
	 * @param logDateFormat
	 */
	public static void configure(String accountLogPattern, String accountLogOrder, String logDateFormat, String timeZone) {
		PATTERN = Pattern.compile(accountLogPattern);
		orderString = accountLogOrder;
		mLogDateFormat = logDateFormat;
		mTimeZone = timeZone;
	}
	
}
