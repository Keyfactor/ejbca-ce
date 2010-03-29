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
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.PatternLogger;

/**
 * This class is used for logging ocsp-responses with the purpose of auditing.
 * It can be used to store entire ocsp-requests and responses which means the log can be used to verify requests afterwards.
 * 
 * @author tham
 * @version $Id$
 */
public class AuditLogger { 
	private final Pattern PATTERN;
	private final String orderString;
    private final Logger accountLog = Logger.getLogger(AuditLogger.class.getName());
	private final String mLogDateFormat ;
	private final String mTimeZone;
	
	//TRY_LATER = 3;SIG_REQUIRED = 5;UNAUTHORIZED = 6;
	 /** regexp pattern to match ${identifier} patterns */// ${DN};${IP}

    /**
	 * Use this method to avoid having parts of the order-string logged when some values have not been stored before a writeln()
	 */
    public IPatternLogger getPatternLogger() {
        IPatternLogger pl = new PatternLogger(this.PATTERN.matcher(this.orderString), this.orderString, this.accountLog, this.mLogDateFormat, this.mTimeZone);
		pl.paramPut(IOCSPLogger.CLIENT_IP,"0");
		pl.paramPut(IAuditLogger.OCSPREQUEST, "0");
		pl.paramPut(IAuditLogger.OCSPRESPONSE, "0");
		pl.paramPut(IOCSPLogger.STATUS, "-1");
		pl.paramPut(IAuditLogger.PROCESS_TIME, "-1");
        return pl;
	}
	
	/**
	 * This Method needs to be called before creating any instances
	 * 
	 * @param accountLogPattern  
	 * @param accountLogOrder
	 * @param logDateFormat
	 */
	public AuditLogger(String accountLogPattern, String accountLogOrder, String logDateFormat, String timeZone) {
		this.PATTERN = Pattern.compile(accountLogPattern);
		this.orderString = accountLogOrder;
		this.mLogDateFormat = logDateFormat;
		this.mTimeZone = timeZone;
	}
	
}
