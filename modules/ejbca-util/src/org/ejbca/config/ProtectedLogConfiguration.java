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

import org.apache.log4j.Logger;

/**
 * This file handles configuration from logdevices/protectedlog.properties
 */
public class ProtectedLogConfiguration {

	public final static String CONFIG_TOKENREFTYPE           = "protectionTokenReferenceType";
	public final static String CONFIG_TOKENREFTYPE_NONE      = "none"; 
	public final static String CONFIG_TOKENREFTYPE_CANAME    = "CAName"; 
	public final static String CONFIG_TOKENREFTYPE_URI       = "URI"; 
	public final static String CONFIG_TOKENREFTYPE_DATABASE  = "StoredInDatabase"; 
	public final static String CONFIG_TOKENREFTYPE_CONFIG    = "Base64EncodedConfig";
	public final static String CONFIG_TOKENREF               = "protectionTokenReference";
	public final static String CONFIG_KEYSTOREALIAS          = "protectionTokenKeyStoreAlias";
	public final static String CONFIG_KEYSTOREPASSWORD       = "protectionTokenKeyStorePassword";
	public final static String CONFIG_HASHALGO               = "protectionHashAlgorithm";
	public final static String CONFIG_NODEIP                 = "nodeIP";
	public final static String CONFIG_PROTECTION_INTENSITY   = "protectionIntensity";
	public final static String CONFIG_MAX_VERIFICATION_STEPS = "maxVerificationsSteps";
	public final static String CONFIG_ALLOW_EVENTSCONFIG     = "allowConfigurableEvents";
	public final static String CONFIG_LINKIN_INTENSITY       = "linkinIntensity";
	public final static String CONFIG_VERIFYOWN_INTENSITY    = "verifyownIntensity";
	public final static String CONFIG_SEARCHWINDOW           = "searchWindow";
	public final static String CONFIG_USEDUMMYACTION         = "useDummyAction";
	public final static String CONFIG_USESCRIPTACTION        = "useScriptAction";
	public final static String CONFIG_USEMAILACTION          = "useMailAction";
	public final static String CONFIG_USESHUTDOWNACTION      = "useShutDownAction";
	public final static String CONFIG_USETESTACTION          = "useTestAction";
	public static final String CONFIG_SA_TARGET_SCRIPT       = "scriptAction.target";
	public static final String CONFIG_MA_EMAILADDRESSES      = "mailAction.emailAddresses";
	public static final String CONFIG_MA_EMAILSUBJECT        = "mailAction.subject";
	public static final String CONFIG_MA_EMAILBODY           = "mailAction.body";
	public static final String CONFIG_MA_EMAILSENDER         = "mailAction.senderAddress";
	public static final String CONFIG_CMS_EXPORTPATH         = "cmsexport.fullpath";
	public static final String CONFIG_CMS_CANAME             = "cmsexport.caname";
	public static final String CONFIG_EXP_HASHALGO           = "exportservice.hashAlgorithm";
	public static final String CONFIG_EXP_DELETEAFTEREXPORT  = "exportservice.deleteafterexport";
	public static final String CONFIG_EXP_EXPORTOLDERTHAN    = "exportservice.exportolderthan";
	public static final String CONFIG_EXP_EXPORTHANDLER      = "exportservice.exporthandler";
	public static final String CONFIG_EXP_SERVICEINTERVAL    = "exportservice.invokationinterval";
	public static final String CONFIG_VFY_FREEZETHRESHOLD    = "verificationservice.freezetreshold";
	public static final String CONFIG_VFY_SERVICEINTERVAL    = "verificationservice.invokationinterval";

	public final static int TOKENREFTYPE_NONE     = 0; 
	public final static int TOKENREFTYPE_CANAME   = 1; 
	public final static int TOKENREFTYPE_URI      = 2; 
	public final static int TOKENREFTYPE_DATABASE = 3; 
	public final static int TOKENREFTYPE_CONFIG   = 4;
	
	private static final Logger log = Logger.getLogger(ProtectedLogConfiguration.class);

	/**
	 * protectionToken is the key used to protect log-rows in the database.
	 */
	public static int getProtectionTokenReferenceType() {
		String value = ConfigurationHolder.getString(CONFIG_TOKENREFTYPE, CONFIG_TOKENREFTYPE_NONE);
		if (CONFIG_TOKENREFTYPE_CANAME.equalsIgnoreCase(value)) {
			return TOKENREFTYPE_CANAME;
		} else if (CONFIG_TOKENREFTYPE_URI.equalsIgnoreCase(value)) {
			return TOKENREFTYPE_URI;
		} else if (CONFIG_TOKENREFTYPE_DATABASE.equalsIgnoreCase(value)) {
			return TOKENREFTYPE_DATABASE;
		}
		return TOKENREFTYPE_NONE;
	}

	/**
	 * Get a reference to the token used to protect the logs
	 */
	public static String getTokenReference() {
		return ConfigurationHolder.getString(CONFIG_TOKENREF, "AdminCA1");
	}
	
	/**
	 * Get the used alias in the KeyStore
	 */
	public static String getKeyStoreAlias() {
		return ConfigurationHolder.getString(CONFIG_KEYSTOREALIAS, "defaultKey");
	}
	
	/**
	 * Get the used password for the KeyStore
	 */
	public static String getKeyStorePassword() {
		return ConfigurationHolder.getString(CONFIG_KEYSTOREPASSWORD, "foo123");
	}
	
	/**
	 * The nodes IP
	 */
	public static String getNodeIp(String defaultIp) {
		return ConfigurationHolder.getString(CONFIG_NODEIP, defaultIp);
	}
	
	/**
	 * How often each node should sign a log-row in seconds.
	 */
	public static long getProtectionIntensity() {
		long value = 0;
		try {
			value = Long.parseLong(ConfigurationHolder.getString(CONFIG_PROTECTION_INTENSITY, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_PROTECTION_INTENSITY+"\" is not a decimal number. Using default value: " + value);
		}
		return value*1000L;
	}
	
	/**
	 * For how many steps of a chain should the algorithm try to find a sealing
	 * signature before concluding "undetermined" when displaying events.
	 * -1 disable verification, 0 undetermined if the requested event isn't signed.
	 * Default is "0" which makes sense if protectionIntensity is "0"
	 */
	public static int getMaxVerificationSteps() {
		int value = 0;
		try {
			value = Integer.parseInt(ConfigurationHolder.getString(CONFIG_MAX_VERIFICATION_STEPS, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_MAX_VERIFICATION_STEPS+"\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}
	
	/**
	 * Allow administrators with access to Admin GUI Log Configuration to disable logging of
	 * certain events
	 */
	public static boolean getAllowEventConfig() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_ALLOW_EVENTSCONFIG, "false"));
	}
	
	/**
	 * Link-in intensity: how often to search for new log-rows from other nodes in seconds.
	 * -1 disabled, 0 always search
	 */
	public static long getLinkInIntensity() {
		long value = 1;
		try {
			value = Long.parseLong(ConfigurationHolder.getString(CONFIG_LINKIN_INTENSITY, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_LINKIN_INTENSITY+"\" is not a decimal number. Using default value: " + value);
		}
		return value*1000L;
	}
	
	/**
	 * Verification intensity of own log-events: how often to search for the last written log-row in seconds.
	 * -1 disabled, 0 always search
	 */
	public static long getVerifyOwnIntensity() {
		long value = 1;
		try {
			value = Long.parseLong(ConfigurationHolder.getString(CONFIG_VERIFYOWN_INTENSITY, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_VERIFYOWN_INTENSITY+"\" is not a decimal number. Using default value: " + value);
		}
		return value*1000L;
	}
	
	/**
	 * How far back to search for events.
	 */
	public static long getSearchWindow() {
		long value = 300;
		try {
			value = Long.parseLong(ConfigurationHolder.getString(CONFIG_SEARCHWINDOW, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_SEARCHWINDOW+"\" is not a decimal number. Using default value: " + value);
		}
		return value*1000L;
	}
	
	/**
	 * The hash algorithm used for chaining
	 */
	public static String getHashAlgorithm() {
		return ConfigurationHolder.getString(CONFIG_HASHALGO, "SHA-256");
	}

	/**
	 * Use Dummy Action
	 */
	public static boolean getUseDummyAction() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_USEDUMMYACTION, "false"));
	}
	
	/**
	 * Use Script Action
	 */
	public static boolean getUseScriptAction() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_USESCRIPTACTION, "false"));
	}
	
	/**
	 * Use Mail Action
	 */
	public static boolean getUseMailAction() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_USEMAILACTION, "false"));
	}
	
	/**
	 * Use Shut Down Action
	 */
	public static boolean getUseShutDownAction() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_USESHUTDOWNACTION, "false"));
	}
	
	/**
	 * Use Test Action
	 */
	public static boolean getUseTestAction() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_USETESTACTION, "false"));
	}
	
	/**
	 * Get Script used by ScriptAction
	 */
	public static String getScriptActionScript() {
		String ret = ConfigurationHolder.getString(CONFIG_SA_TARGET_SCRIPT, null);
		if ("".equals("")) {
			ret = null;
		}
		return ret;
	}
	
	/**
	 * Get MailAction's email address(es)
	 */
	public static String[] getMailActionEmailAddresses() {
		String[] ret = new String[0];
		String emailAddressesString = ConfigurationHolder.getString(CONFIG_MA_EMAILADDRESSES, "");
		if (emailAddressesString.length() > 0) {
			ret = emailAddressesString.split(";");
		}
		return ret;
	}
	
	/**
	 * Get MailAction's sender
	 */
	public static String getMailActionEmailSender() {
		return ConfigurationHolder.getString(CONFIG_MA_EMAILSENDER, "no-reply@company.com");
	}
	
	/**
	 * Get MailAction's subject
	 */
	public static String getMailActionEmailSubject() {
		return ConfigurationHolder.getString(CONFIG_MA_EMAILSUBJECT, "Possible log tampering detected");
	}

	/**
	 * Get MailAction's body
	 */
	public static String getMailActionEmailBody() {
		return ConfigurationHolder.getString(CONFIG_MA_EMAILBODY, "This mail was auto-generated by EJBCA.");
	}
	
	/**
	 * Get CMS export path
	 */
	public static String getCMSExportPath() {
		return ConfigurationHolder.getString(CONFIG_CMS_EXPORTPATH, "");
	}
	
	/**
	 * Get CMS export CA name
	 */
	public static String getCMSCaName() {
		return ConfigurationHolder.getString(CONFIG_CMS_CANAME, "AdminCA1");
	}
	
	/**
	 * Get export hash algorithm
	 */
	public static String getExportHashAlgorithm() {
		return ConfigurationHolder.getString(CONFIG_EXP_HASHALGO, "SHA-256");
	}
	
	/**
	 * Get export handler classname
	 */
	public static String getExportHandlerClassName() {
		return ConfigurationHolder.getString(CONFIG_EXP_EXPORTHANDLER, "org.ejbca.core.model.log.ProtectedLogDummyExportHandler");
	}
	
	/**
	 * Delete log entries after they are exported?
	 */
	public static boolean getExportDeleteAfterExport() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString(CONFIG_EXP_DELETEAFTEREXPORT, "false"));
	}
	
	/**
	 * @return how old log entries can be before they are exported in milliseconds 
	 */
	public static long getExportOlderThan() {
		long value = 0;
		try {
			value = Long.parseLong(ConfigurationHolder.getString(CONFIG_EXP_EXPORTOLDERTHAN, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_EXP_EXPORTOLDERTHAN+"\" is not a decimal number. Using default value: " + value);
		}
		return value*60L*1000L;
	}
	
	/**
	 * @return how old the newest log entry for a node can be before the node is considered frozen in milliseconds 
	 */
	public static long getVerifyFreezeThreshold() {
		long value = 180;
		try {
			value = Long.parseLong(ConfigurationHolder.getString(CONFIG_VFY_FREEZETHRESHOLD, ""+value));
		} catch( NumberFormatException e ) {
			log.warn("\""+CONFIG_VFY_FREEZETHRESHOLD+"\" is not a decimal number. Using default value: " + value);
		}
		return value*60L*1000L;
	}

	/**
	 * Return true if export service should be active 
	 */
	public static boolean getExportServiceActive() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString("exportservice.active", "false"));
	}
	
	/**
	 * Get export service interval
	 */
	public static String getExportServiceInterval() {
		return ConfigurationHolder.getString(CONFIG_EXP_SERVICEINTERVAL, "1440");
	}
	
	/**
	 * Get verification service interval
	 */
	public static String getVerificationServiceInterval() {
		return ConfigurationHolder.getString(CONFIG_VFY_SERVICEINTERVAL, "120");
	}
	
	/**
	 * Return true if verification service should be active 
	 */
	public static boolean getVerificationServiceActive() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString("verificationservice.active", "false"));
	}
	
	
}
