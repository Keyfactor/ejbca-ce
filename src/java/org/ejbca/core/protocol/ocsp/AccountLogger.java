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
import java.util.regex.Matcher;
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
public class AccountLogger extends PatternLogger { 
	private static Pattern PATTERN;
	private static String orderString;
	private static Matcher m_matcher;
    private static final Logger accountLog = Logger.getLogger(AccountLogger.class.getName());
	private static String mLogDateFormat ;
	public static final String LOG_ID="LOG_ID";//A random 32 bit number identifying a log entry for a request
	public static final String CLIENT_IP="CLIENT_IP";//IP of the client making the request
	public static final String SERIAL_NOHEX = "SERIAL_NOHEX"; // The serial number of the requested certificate
	public static final String OCSPREQUEST = "OCSPREQUEST";	//The byte[] ocsp-request that came with the http-request
	public static final String OCSPRESPONSE = "OCSPRESPONSE"; //The byte[] ocsp-response that was included in the http-response
	public static final String ISSUER_NAME_HASH = "ISSUER_NAME_HASH"; // The DN of the issuer of the requested
	public static final String ISSUER_KEY = "ISSUER_KEY";
	
	//TRY_LATER = 3;SIG_REQUIRED = 5;UNAUTHORIZED = 6;
	 /** regexp pattern to match ${identifier} patterns */// ${DN};${IP}

	public AccountLogger () {
		super(PATTERN.matcher(orderString), orderString, accountLog, mLogDateFormat);
		cleanParams();
		super.paramPut(AuditLogger.LOG_ID, GUIDGenerator.generateGUID(this));
        super.paramPut(AuditLogger.LOG_TIME, new Date().toString());
	}
	
	/**
	 * Use this method to avoid having parts of the order-string logged when some values have not been stored before a writeln()
	 */
	protected void cleanParams() {
		super.cleanParams();
		super.paramPut(AuditLogger.LOG_ID, "0");
		super.paramPut(CLIENT_IP,"0");
		super.paramPut(OCSPREQUEST, "0");
		super.paramPut(OCSPRESPONSE, "0");
	}
	
	/**
	 * This Method needs to be called before creating any instances
	 * 
	 * @param accountLogPattern  
	 * @param accountLogOrder
	 * @param logDateFormat
	 */
	public static void configure(String accountLogPattern, String accountLogOrder, String logDateFormat) {
		PATTERN = Pattern.compile(accountLogPattern);
		orderString = accountLogOrder;
		m_matcher = PATTERN.matcher(orderString);
		mLogDateFormat = logDateFormat;
	}
}
