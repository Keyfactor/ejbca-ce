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

public class CmpConfiguration {
	
	public static final String CONFIG_DEFAULTCA               = "cmp.defaultca";
	public static final String CONFIG_ALLOWRAVERIFYPOPO       = "cmp.allowraverifypopo";
	public static final String CONFIG_OPERATIONMODE           = "cmp.operationmode";
	public static final String CONFIG_RA_AUTHENTICATIONSECRET = "cmp.ra.authenticationsecret";
	public static final String CONFIG_RA_ENDENTITYPROFILE     = "cmp.ra.endentityprofile";
	public static final String CONFIG_RA_CERTIFICATEPROFILE   = "cmp.ra.certificateprofile";
	public static final String CONFIG_RESPONSEPROTECTION      = "cmp.responseprotection";

	public static boolean getAllowRAVerifyPOPO() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString(CONFIG_ALLOWRAVERIFYPOPO, "false"));
	}
	
	public static String getDefaultCA() {
		return ConfigurationHolder.getString(CONFIG_DEFAULTCA, null);
	}
	
	public static String getExtractUsernameComponent() {
		return ConfigurationHolder.getString("cmp.extractusernamecomponent", null);
	}
	
	public static boolean getRAOperationMode() {
		return "ra".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_OPERATIONMODE, "normal"));
	}
	
	public static String getRANameGenerationScheme() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationscheme", "DN");
	}
	
	public static String getRANameGenerationParameters() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationparameters", "CN");
	}
	
	public static String getRANameGenerationPrefix() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationprefix", null);
	}
	
	public static String getRANameGenerationPostfix() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationpostfix", null);
	}
	
	public static String getUserPasswordParams() {
		return ConfigurationHolder.getString("cmp.ra.passwordgenparams", "random");		
	}
	
	public static String getRAAuthenticationSecret() {
		return ConfigurationHolder.getString(CONFIG_RA_AUTHENTICATIONSECRET, null);
	}
	
	public static String getRAEndEntityProfile() {
		return ConfigurationHolder.getString(CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
	}
	
	public static String getRACertificateProfile() {
		return ConfigurationHolder.getString(CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
	}
	
	public static String getRACAName() {
		return ConfigurationHolder.getString("cmp.ra.caname", "AdminCA1");
	}
	
	public static String getResponseProtection() {
		return ConfigurationHolder.getString(CONFIG_RESPONSEPROTECTION, "signature");
	}
	
	public static int getTCPPortNumber() {
		return new Integer(ConfigurationHolder.getString("cmp.tcp.portno", "829")).intValue();
	}
	
	public static String getTCPLogDir() {
		return ConfigurationHolder.getString("cmp.tcp.logdir", "./log");
	}
	
	public static String getTCPConfigFile() {
		return ConfigurationHolder.getString("cmp.tcp.conffile", "");
	}
	
	public static String getTCPBindAdress() {
		return ConfigurationHolder.getString("cmp.tcp.bindadress", "0.0.0.0");
	}
	
	
}
