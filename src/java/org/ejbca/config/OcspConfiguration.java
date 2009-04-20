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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.protocol.ocsp.OCSPUtil;

/**
 * Parses configuration bundled in conf/ocsp.properties, both for the internal and external OCSP responder.
 * 
 * @version $Id$
 */
public class OcspConfiguration {

	private static final Logger log = Logger.getLogger(OcspConfiguration.class);

	public static final int RESTRICTONISSUER = 0;
	public static final int RESTRICTONSIGNER = 1;

	/**
	 * Algorithm used by server to generate signature on OCSP responses
	 */
	public static String getSignatureAlgorithm() {
		return ConfigurationHolder.getString("ocsp.signaturealgorithm", "SHA1WithRSA;SHA1WithECDSA");
	}

	/**
	 * The interval on which new OCSP signing certificates are loaded in seconds
	 */
	public static int getSigningCertsValidTime() {
		int value = 300;
		try {
			value = Integer.parseInt(ConfigurationHolder.getString("ocsp.signingCertsValidTime", ""+value)) * 1000;
		} catch( NumberFormatException e ) {
			log.warn("\"ocsp.signingCertsValidTime\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}

	/**
	 * If set to true the Servlet will enforce OCSP request signing
	 */
	public static boolean getEnforceRequestSigning() {
		String value = ConfigurationHolder.getString("ocsp.signaturerequired", "false");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * If set to true the Servlet will restrict OCSP request signing
	 */
	public static boolean getRestrictSignatures() {
		String value = ConfigurationHolder.getString("ocsp.restrictsignatures", "false");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * Set this to issuer or signer depending on how you want to restrict allowed signatures for OCSP request signing.
	 * @returns one of OcspConfiguration.RESTRICTONISSUER and OcspConfiguration.RESTRICTONSIGNER
	 */
	public static int getRestrictSignaturesByMethod() {
		if ("signer".equalsIgnoreCase(ConfigurationHolder.getString("ocsp.restrictsignaturesbymethod", "issuer"))) {
			return RESTRICTONSIGNER;
		}
		return RESTRICTONISSUER;
	}

	/**
	 * If ocsp.restrictsignatures is true the Servlet will look in this directory for allowed signer certificates or issuers.
	 */
	public static String getSignTrustDir() {
		return ConfigurationHolder.getString("ocsp.signtrustdir", null);
	}

	/**
	 * The interval on which list of allowed OCSP request signing certificates are loaded from signTrustDir in seconds.
	 */
	public static int getSignTrustValidTime() {
		int value = 180;
		try {
			value = Integer.parseInt(ConfigurationHolder.getString("ocsp.signtrustvalidtime", ""+value)) * 1000;
		} catch( NumberFormatException e ) {
			log.warn("\"ocsp.signtrustvalidtime\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}

	/**
	 * If set to true the certificate chain will be returned with the OCSP response.
	 */
	public static boolean getIncludeCertChain() {
		String value = ConfigurationHolder.getString("ocsp.includecertchain", "true");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}


	/**
	 * If set to true the OCSP responses will be signed directly by the CAs certificate instead of the CAs OCSP responder.
	 */
	public static boolean getUseCASigningCert() {
		String value = ConfigurationHolder.getString("ocsp.usecasigningcert", "true");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * If set to name the OCSP responses will use the Name ResponseId type, if set to keyhash the KeyHash type will be used.
	 * @returns one of OCSPUtil.RESPONDERIDTYPE_NAME and OCSPUtil.RESPONDERIDTYPE_KEYHASH
	 */
	public static int getResponderIdType() {
		if ("name".equalsIgnoreCase(ConfigurationHolder.getString("ocsp.responderidtype", "keyhash"))) {
			return OCSPUtil.RESPONDERIDTYPE_NAME;
		}
		return OCSPUtil.RESPONDERIDTYPE_KEYHASH;
	}

	/**
	 * If true a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as not revoked.
	 */
	public static boolean getNonExistingIsGood() {
		String value = ConfigurationHolder.getString("ocsp.nonexistingisgood", "false");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * Specifies the subject of a certificate which is used to identify the responder which will
	 * generate responses when no real CA can be found from the request. This is used to generate
	 * 'unknown' responses when a request is received for a certificate that is not signed by any
	 * CA on this server.
	 */
	public static String getDefaultResponderId() {
		return ConfigurationHolder.getExpandedString("ocsp.defaultresponder", "CN=AdminCA1,O=${app.name.cap} Sample,C=SE");
	}

	/**
	 * Specifies OCSP extension OIDs that will result in a call to an extension class, separate multiple entries with ';'.
	 * @return a List<String> of extension OIDs
	 */
	public static List getExtensionOids() {
		String value = ConfigurationHolder.getString("ocsp.extensionoid", "");
		if ("".equals(value)) {
			return new ArrayList();
		}
		return Arrays.asList(value.split(";"));
	}

	/**
	 * Specifies classes implementing OCSP extensions matching OIDs in getExtensionOid(), separate multiple entries with ';'.
	 * @return a List<String> of extension classes
	 */
	public static List getExtensionClasses() {
		String value = ConfigurationHolder.getString("ocsp.extensionclass", "");
		if ("".equals(value)) {
			return new ArrayList();
		}
		return Arrays.asList(value.split(";"));
	}

	/**
	 * DataSource for Unid-Fnr mapping OCSP extension.
	 */
	public static String getUnidDataSource() {
		return ConfigurationHolder.getString("ocsp.uniddatsource", "");
	}

	/**
	 * Directory containing certificates of trusted entities allowed to query for Fnrs.
	 */
	public static String getUnidTrustDir() {
		return ConfigurationHolder.getString("ocsp.unidtrustdir", "");
	}

	/**
	 * File containing the CA-certificate, in PEM format, that signed the trusted clients.
	 */
	public static String getUnidCaCert() {
		return ConfigurationHolder.getString("ocsp.unidcacert", "");
	}

	/**
	 * When true, an audit log will be created.
	 */
	public static boolean getAuditLog() {
		String value = ConfigurationHolder.getString("ocsp.audit-log", "false");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * A format string for logging of dates in auditLog and accountLog.
	 */
	public static String getLogDateFormat() {
		return ConfigurationHolder.getString("ocsp.log-date", "yyyy-MM-dd:HH:mm:ss:z");
	}

	/**
	 * A format string for TimeZone auditLog and accountLog.
	 */
	public static String getLogTimeZone() {
		return ConfigurationHolder.getString("ocsp.log-timezone", "GMT");
	}

	/**
	 * Set to true if you want transactions to be aborted when logging fails.
	 */
	public static boolean getLogSafer() {
		String value = ConfigurationHolder.getString("ocsp.log-safer", "false");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * A String to create a java Pattern to format the audit Log
	 */
	public static String getAuditLogPattern() {
		return ConfigurationHolder.getString("ocsp.audit-log-pattern", "\\$\\{(.+?)\\}");
	}

	/**
	 * A String which combined with auditLogPattern determines how auditLog output is formatted.
	 */
	public static String getAuditLogOrder() {
		String value = ConfigurationHolder.getString("ocsp.audit-log-order", "SESSION_ID:${SESSION_ID};LOG ID:${LOG_ID};\"${LOG_TIME}\""
				+ ";TIME TO PROCESS:${REPLY_TIME};\nOCSP REQUEST:\n\"${OCSPREQUEST}\";\nOCSP RESPONSE:\n\"${OCSPRESPONSE}\";\nSTATUS:${STATUS}");
		value = value.replace("\\\"", "\"");	// From EJBCA 3.9 the "-char does not need to be escaped, but we want to be backward compatible 
		return value;
	}

	/**
	 * When true, a transaction log will be created.
	 */
	public static boolean getTransactionLog() {
		String value = ConfigurationHolder.getString("ocsp.trx-log", "false");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}

	/**
	 * A String to create a java Pattern to format the transaction Log.
	 */
	public static String getTransactionLogPattern() {
		return ConfigurationHolder.getString("ocsp.trx-log-pattern", "\\$\\{(.+?)\\}");
	}

	/**
	 * A String which combined with transactionLogPattern determines how transaction Log output is formatted.
	 */
	public static String getTransactionLogOrder() {
		String value = ConfigurationHolder.getString("ocsp.trx-log-order", "${SESSION_ID};${LOG_ID};${STATUS};${REQ_NAME}\"${CLIENT_IP}\";"
				+"\"${SIGN_ISSUER_NAME_DN}\";\"${SIGN_SUBJECT_NAME}\";${SIGN_SERIAL_NO};\"${LOG_TIME}\";${REPLY_TIME};${NUM_CERT_ID};0;0;0;0;0;0;0;"
				+"\"${ISSUER_NAME_DN}\";${ISSUER_NAME_HASH};${ISSUER_KEY};${DIGEST_ALGOR};${SERIAL_NOHEX};${CERT_STATUS}");
		value = value.replace("\\\"", "\"");	// From EJBCA 3.9 the "-char does not need to be escaped, but we want to be backward compatible 
		return value;
	}

	/**
	 * The default number of seconds a request is valid or 0 to disable.
	 */
	public static long getUntilNextUpdate() {
		long value = 0;
		try {
			value = Integer.parseInt(ConfigurationHolder.getString("ocsp.untilNextUpdate", ""+value)) * 1000;
		} catch( NumberFormatException e ) {
			log.warn("\"ocsp.signtrustvalidtime\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}

	/**
	 * The default number of seconds a HTTP-response should be cached.
	 */
	public static long getMaxAge() {
		long value = 30;
		try {
			value = Integer.parseInt(ConfigurationHolder.getString("ocsp.maxAge", ""+value)) * 1000;
		} catch( NumberFormatException e ) {
			log.warn("\"ocsp.signtrustvalidtime\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}
	
	// Values for stand-alone OCSP
	
	/**
	 * Directory name of the soft keystores. The signing keys will be fetched from all files in this directory.
	 * Valid formats of the files are JKS and PKCS12 (p12)."
	 */
	public static String getSoftKeyDirectoryName() {
		return ConfigurationHolder.getString("ocsp.keys.dir", "./keys");
	}
	
	/**
	 * The password for the all the soft keys of the OCSP responder.
	 */
	public static String getKeyPassword() {
		return ConfigurationHolder.getString("ocsp.keys.keyPassword", "foo123");
	}
	
	/**
	 * The password to all soft keystores.
	 * @return the value of getKeyPassword() if property isn't set.
	 */
	public static String getStorePassword() {
		String value = ConfigurationHolder.getString("ocsp.keys.storePassword", "");
		if (value == null || value.length()==0) {
			value = getKeyPassword();
		}
		return value;
	}
	
	/**
	 * The password for all keys stored on card.
	 */
	public static String getCardPassword() {
		return ConfigurationHolder.getString("ocsp.keys.cardPassword", "");
	}
	
	/**
	 * The class that implements card signing of the OCSP response.
	 */
	public static String getHardTokenClassName() {
		return ConfigurationHolder.getString("ocsp.hardToken.className", "se.primeKey.caToken.card.CardKeysImpl");
	}

    /**
     * @return Sun P11 configuration file name.
     */
    public static String getSunP11ConfigurationFile() {
        return ConfigurationHolder.getString("ocsp.p11.sunConfigurationFile", "");
    }

    /**
     * @return time before the experation of the OCSP signing cert that the signing key should be renewed.
     */
    public static int getRenewTimeBeforeCertExpiresInSeconds() {
        final String key = "ocsp.renewTimeBeforeCertExpiresInSeconds";
        final String sValue = ConfigurationHolder.getString(key, "");
        if ( sValue==null || sValue.length()<1 ) {
            return -1;
        }
        try {
            return Integer.parseInt(sValue);
        } catch ( NumberFormatException e ) {
            log.error("Could not parse value of "+key+" to integer.", e);
        }
        return -1;
    }

    /**
     * @return EJBCA web service URL
     */
    public static String getEjbcawsracliUrl() {
        return ConfigurationHolder.getString("ocsp.ejbcawsracli.url", "");
    }

	/**
	 * P11 shared library path name.
	 */
	public static String getSharedLibrary() {
		return ConfigurationHolder.getString("ocsp.p11.sharedLibrary", "");
	}
	
	/**
	 * P11 password.
	 */
	public static String getP11Password() {
		return ConfigurationHolder.getString("ocsp.p11.p11password", "foo123");
	}
	
	/**
	 * P11 slot number.
	 */
	public static String getSlot() {
		return ConfigurationHolder.getString("ocsp.p11.slot", "i1");
	}
}
