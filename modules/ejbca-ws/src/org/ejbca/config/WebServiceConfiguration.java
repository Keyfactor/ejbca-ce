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

package org.ejbca.config;

import org.apache.log4j.Logger;

/**
 * Configuration from jaxws.properties
 * 
 * @version $Id$
 */
public class WebServiceConfiguration {

	private static final Logger log = Logger.getLogger(WebServiceConfiguration.class);
	
	/**
	 * Indicating if a call to getHardTokenData for non-authorized users should result in an
	 * approval request instead of an authorized denied exception.
	 */
	public static boolean getApprovalForHardTokenData() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString("jaxws.approval.gethardtoken"));
	}

	/**
	 * Indicating if a call to genTokenCertificates for non-authorized users should result in an
	 * approval request instead of an authorized denied exception.
	 */
	public static boolean getApprovalForGenTokenCertificates() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString("jaxws.approval.gentokencerts"));
	}

	/**
	 * Indicating the number of approvals required to allow an action for a non-authorized
	 * administrator.
	 */
	public static int getNumberOfRequiredApprovals() {
		int value = 1;
		try {
			value = Integer.parseInt(EjbcaConfigurationHolder.getString("jaxws.numberofrequiredapprovals"));
		} catch( NumberFormatException e ) {
			log.warn("\"jaxws.numberofrequiredapprovals\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}

	/**
	 * Authorization control on the fetchUserData call, making it possible for all with a valid
     * certificate to retrieve userData
	 */
	public static boolean getNoAuthorizationOnFetchUserData() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString("jaxws.noauthonfetchuserdata"));
	}

	/**
	 * If this is true, all certificates on the old token will be put on hold.
	 * If this is false, MS SmartCard Logon certificates will not be put on hold.
	 * This is used when a temporary card is issued with ToLiMa, since MS doesn't
	 * work well with temporarily revoked smartcards.
	 */
	public static boolean getSuspendAllCertificates() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString("jaxws.gentokens.setmslogononhold"));
	}

	/**
	 * Use transaction logging for all WS calls.
	 */
	public static boolean getTransactionLogEnabled() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString("ejbcaws.trx-log"));
	}
	
	/**
	 * Returns the date and time format that will be used for transaction logging. 
	 */
	public static String getTransactionLogDateFormat() {
		return EjbcaConfigurationHolder.getString("ejbcaws.log-date");
	}
	
	/**
	 * Returns the time zone that will be used for transaction logging. 
	 */
	public static String getTransactionLogTimeZone() {
		return EjbcaConfigurationHolder.getExpandedString("ejbcaws.log-timezone");
	}
	
	/**
	 * Returns the matching pattern that will be used for transaction logging. 
	 */
	public static String getTransactionLogPattern() {
		return EjbcaConfigurationHolder.getString("ejbcaws.trx-log-pattern");
	}
	
	/**
	 * Returns the the base string that will be substituted during transaction logging. 
	 */
	public static String getTransactionLogOrder() {
		return EjbcaConfigurationHolder.getString("ejbcaws.trx-log-order");
	}
	
}
