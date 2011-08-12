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
	public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO = "cmp.ra.allowcustomcertserno";
	public static final String CONFIG_RA_NAMEGENERATIONSCHEME = "cmp.ra.namegenerationscheme";
	public static final String CONFIG_RA_NAMEGENERATIONPARAMS = "cmp.ra.namegenerationparameters";
	public static final String CONFIG_RA_AUTHENTICATIONSECRET = "cmp.ra.authenticationsecret";
	public static final String CONFIG_RA_ENDENTITYPROFILE     = "cmp.ra.endentityprofile";
	public static final String CONFIG_RA_CERTIFICATEPROFILE   = "cmp.ra.certificateprofile";
	public static final String CONFIG_RESPONSEPROTECTION      = "cmp.responseprotection";
	public static final String CONFIG_RACANAME				  = "cmp.ra.caname";
	public static final String CONFIG_CERTREQHANDLER_CLASS    = "cmp.certreqhandler.class";
	public static final String CONFIG_UNIDDATASOURCE		  = "cmp.uniddatasource";

	/**
	 * This defines if we allows messages that has a POPO setting of raVerify. 
	 * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
	 */
	public static boolean getAllowRAVerifyPOPO() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWRAVERIFYPOPO, "false"));
	}
	
	/** The default CA used for signing requests, if it is not given in the request itself. */
	public static String getDefaultCA() {
		return EjbcaConfigurationHolder.getString(CONFIG_DEFAULTCA, null);
	}
	
	/**
	 * Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing.
	 * Nothing means that the DN will be used to look up the user.
	 */
	public static String getExtractUsernameComponent() {
		return EjbcaConfigurationHolder.getString("cmp.extractusernamecomponent", null);
	}
	
	public static boolean getRAOperationMode() {
		return "ra".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_OPERATIONMODE, "normal"));
	}
	
	public static String getRANameGenerationScheme() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_NAMEGENERATIONSCHEME, "DN");
	}
	
	public static String getRANameGenerationParameters() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_NAMEGENERATIONPARAMS, "CN");
	}
	
	public static String getRANameGenerationPrefix() {
		return EjbcaConfigurationHolder.getString("cmp.ra.namegenerationprefix", null);
	}
	
	public static String getRANameGenerationPostfix() {
		return EjbcaConfigurationHolder.getString("cmp.ra.namegenerationpostfix", null);
	}
	
	public static String getUserPasswordParams() {
		return EjbcaConfigurationHolder.getString("cmp.ra.passwordgenparams", "random");		
	}
	
	public static String getRAAuthenticationSecret() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_AUTHENTICATIONSECRET, null);
	}
	
	public static String getRAEndEntityProfile() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
	}
	
	public static String getRACertificateProfile() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
	}
	
	public static String getRACAName() {
		return EjbcaConfigurationHolder.getString(CONFIG_RACANAME, "AdminCA1");
	}
	
	public static String getResponseProtection() {
		return EjbcaConfigurationHolder.getString(CONFIG_RESPONSEPROTECTION, "signature");
	}
	
	public static int getTCPPortNumber() {
		return Integer.valueOf(EjbcaConfigurationHolder.getString("cmp.tcp.portno", "829")).intValue();
	}
	
	public static String getTCPLogDir() {
		return EjbcaConfigurationHolder.getString("cmp.tcp.logdir", "./log");
	}
	
	public static String getTCPConfigFile() {
		return EjbcaConfigurationHolder.getString("cmp.tcp.conffile", "");
	}
	
	public static String getTCPBindAdress() {
		return EjbcaConfigurationHolder.getString("cmp.tcp.bindadress", "0.0.0.0");
	}
	
	public static boolean getRAAllowCustomCertSerno() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_RA_ALLOWCUSTOMCERTSERNO, "false"));
	}

	public static String getUnidDataSource() {
		return EjbcaConfigurationHolder.getString(CONFIG_UNIDDATASOURCE, null);
	}

	public static String getCertReqHandlerClass() {
		return EjbcaConfigurationHolder.getString(CONFIG_CERTREQHANDLER_CLASS, null);
	}
}
