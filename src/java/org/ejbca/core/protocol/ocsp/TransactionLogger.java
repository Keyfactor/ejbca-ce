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
 * This class is used for logging information about ocsp-requests.
 * 
 * @author tham
 * @version $Id$
 *
 */
public class TransactionLogger {

	public static final Logger auditlog = Logger.getLogger(TransactionLogger.class.getName());

	/** regexp pattern to match ${identifier} patterns */// ${DN};${IP}
	// private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}"); // TODO this should be configurable from file
	final private Pattern PATTERN;// = Pattern.compile("\\$\\{(.+?)\\}");// TODO this should be configurable from file

	//  = "${LOG_ID};${STATUS};\"${CLIENT_IP}\";\"${SIGN_ISSUER_NAME_DN}\";\"${SIGN_SUBJECT_NAME}\";${SIGN_SERIAL_NO};" +
	// 		"\"${LOG_TIME}\";${NUM_CERT_ID};0;0;0;0;0;0;0;" +
	//		"\"${ISSUER_NAME_DN}\";${ISSUER_NAME_HASH};${ISSUER_KEY};${DIGEST_ALGOR};${SERIAL_NOHEX};${CERT_STATUS}";
	final private String orderString;
	final private String mLogDateFormat; 
	final private String mTimeZone;

    public IPatternLogger getPatternLogger() {
        IPatternLogger pl = new PatternLogger(this.PATTERN.matcher(this.orderString), this.orderString, auditlog, this.mLogDateFormat, this.mTimeZone);
        pl.paramPut(IOCSPLogger.STATUS,"0");
        pl.paramPut(IOCSPLogger.CLIENT_IP,"0");
        pl.paramPut(ITransactionLogger.REQ_NAME,"0");
        pl.paramPut(ITransactionLogger.SIGN_ISSUER_NAME_DN,"0");
        pl.paramPut(ITransactionLogger.SIGN_SUBJECT_NAME,"0");
        pl.paramPut(ITransactionLogger.SIGN_SERIAL_NO,"0");
        pl.paramPut(ITransactionLogger.NUM_CERT_ID,"0");
        pl.paramPut(ITransactionLogger.ISSUER_NAME_DN,"0");
        pl.paramPut(IOCSPLogger.ISSUER_NAME_HASH,"0");
        pl.paramPut(IOCSPLogger.ISSUER_KEY,"0");
        pl.paramPut(ITransactionLogger.DIGEST_ALGOR,"0");
        pl.paramPut(IOCSPLogger.SERIAL_NOHEX,"0");
        pl.paramPut(ITransactionLogger.CERT_STATUS,"0");
        pl.paramPut(ITransactionLogger.PROCESS_TIME, "-1");
        return pl;
	}

	/**
	 * This Method needs to be called before creating any instances
	 * 
	 * @param auditLogPattern
	 * @param auditLogOrder
	 * @param logDateFormat
	 */
	public TransactionLogger(String auditLogPattern, String auditLogOrder, String logDateFormat, String timeZone) {
		this.PATTERN = Pattern.compile(auditLogPattern);
		this.orderString = auditLogOrder;
		this.mLogDateFormat = logDateFormat;
		this.mTimeZone = timeZone;
	}
}
