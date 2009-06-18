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
import org.ejbca.util.PatternLogger;

/**
 * This class is used for logging information about ocsp-requests.
 * 
 * @author tham
 * @version $Id$
 *
 */
public class TransactionLogger extends PatternLogger implements ITransactionLogger {

	public static final Logger auditlog = Logger.getLogger(TransactionLogger.class.getName());

	/** regexp pattern to match ${identifier} patterns */// ${DN};${IP}
	// private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}"); // TODO this should be configurable from file
	private  static Pattern PATTERN;// = Pattern.compile("\\$\\{(.+?)\\}");// TODO this should be configurable from file

	//  = "${LOG_ID};${STATUS};\"${CLIENT_IP}\";\"${SIGN_ISSUER_NAME_DN}\";\"${SIGN_SUBJECT_NAME}\";${SIGN_SERIAL_NO};" +
	// 		"\"${LOG_TIME}\";${NUM_CERT_ID};0;0;0;0;0;0;0;" +
	//		"\"${ISSUER_NAME_DN}\";${ISSUER_NAME_HASH};${ISSUER_KEY};${DIGEST_ALGOR};${SERIAL_NOHEX};${CERT_STATUS}";
	private  static String orderString;
	private static String mLogDateFormat; 
	private static String mTimeZone;
	public TransactionLogger () {
		super(PATTERN.matcher(orderString), orderString, auditlog, mLogDateFormat, mTimeZone);
		cleanParams();
	}

	/**
	 * This Method needs to be called before creating any instances
	 * 
	 * @param auditLogPattern
	 * @param auditLogOrder
	 * @param logDateFormat
	 */
	public static void configure(String auditLogPattern, String auditLogOrder, String logDateFormat, String timeZone) {
		PATTERN = Pattern.compile(auditLogPattern);
		orderString = auditLogOrder;
		mLogDateFormat = logDateFormat;
		mTimeZone = timeZone;
	}

	protected void cleanParams() {
		super.cleanParams();
		super.paramPut(STATUS,"0");
		super.paramPut(CLIENT_IP,"0");
		super.paramPut(REQ_NAME,"0");
		super.paramPut(SIGN_ISSUER_NAME_DN,"0");
		super.paramPut(SIGN_SUBJECT_NAME,"0");
		super.paramPut(SIGN_SERIAL_NO,"0");
		super.paramPut(NUM_CERT_ID,"0");
		super.paramPut(ISSUER_NAME_DN,"0");
		super.paramPut(ISSUER_NAME_HASH,"0");
		super.paramPut(ISSUER_KEY,"0");
		super.paramPut(DIGEST_ALGOR,"0");
		super.paramPut(SERIAL_NOHEX,"0");
		super.paramPut(CERT_STATUS,"0");
	}
	
	/**
	 * @see org.ejbca.core.protocol.ocsp.ITransactionLogger#flush()
	 */
	public void flush() {
		String logstring = super.logmessage.toString();
		logstring = logstring.replaceAll("REPLY_TIME", "0");
		super.logger.debug(logstring);
	}
	
}
