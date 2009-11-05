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

package org.ejbca.config;


/**
 * This file handles configuration from protection.properties
 */
public class ProtectConfiguration {
	
	//private static final Logger log = Logger.getLogger(ProtectConfiguration.class);
	
	public static final String CONFIG_PROTECTIONENABLED     = "protection.enabled";
	
	public static final String PROTECTIONTYPE_SOFT_HMAC     = "SOFT_HMAC";
	public static final String PROTECTIONTYPE_ENC_SOFT_HMAC = "ENC_SOFT_HMAC";
	
	/**
	 * @return true if protection is enabled
	 */
	public static boolean getProtectionEnabled() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_PROTECTIONENABLED, "false"));
	}

	/**
	 * @return true if protection is enabled for internal database logs
	 */
	public static boolean getLogProtectionEnabled() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString("protection.logprotect", "false"));
	}

	/**
	 * @return true if protection is enabled for the CertificateData table
	 */
	public static boolean getCertProtectionEnabled() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString("protection.certprotect", "false"));
	}
	
	/**
	 * @return true if we should warn if a row is missing
	 */
	public static boolean getWarnOnMissingRow() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString("protection.warnonmissingrow", "true"));
	}
	
	/**
	 * @return the protection key String
	 */
	public static String getProtectionKey() {
		return ConfigurationHolder.getString("protection.key", "foo123");
	}
	
	/**
	 * @return the type of protection used for the key
	 */
	public static String getProtectionKeyType() {
		return ConfigurationHolder.getString("protection.keytype", PROTECTIONTYPE_SOFT_HMAC);
	}
}
