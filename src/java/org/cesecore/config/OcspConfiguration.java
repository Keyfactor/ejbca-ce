/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;

/**
 * Parses configuration bundled in conf/ocsp.properties, both for the internal and external OCSP responder.
 * 
 * Based on EJBCA version: 
 *      OcspConfiguration.java 10696 2010-11-25 17:59:18Z jeklund
 * Based on CESeCore version:
 *      OcspConfiguration.java 933 2011-07-07 18:53:11Z mikek
 * 
 * @version $Id$
 */
public class OcspConfiguration {

    private static final Logger log = Logger.getLogger(OcspConfiguration.class);

    public static final String SIGNING_CERTD_VALID_TIME = "ocsp.signingCertsValidTime";
    public static final String SIGNATUREREQUIRED = "ocsp.signaturerequired";
    public static final String STORE_PASSWORD = "ocsp.keys.storePassword";
    public static final String CARD_PASSWORD = "ocsp.keys.cardPassword";
    public static final String RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS = "ocsp.rekeying.renewTimeBeforeCertExpiresInSeconds";
    public static final String REKEYING_WSURL = "ocsp.rekeying.wsurl";
    public static final String P11_PASSWORD = "ocsp.p11.p11password";
    public static final String DO_NOT_STORE_PASSWORDS_IN_MEMORY = "ocsp.activation.doNotStorePasswordsInMemory";
    public static final String WSSWKEYSTOREPATH = "ocsp.rekeying.swKeystorePath";
    public static final String WSSWKEYSTOREPASSWORD = "ocsp.rekeying.swKeystorePassword";
    public static final String WARNING_BEFORE_EXPERATION_TIME = "ocsp.warningBeforeExpirationTime";
    public static final String OCSP_KEYS_DIR= "ocsp.keys.dir";

    public static final int RESTRICTONISSUER = 0;
    public static final int RESTRICTONSIGNER = 1;

    public static final int RESPONDERIDTYPE_NAME = 1;
    public static final int RESPONDERIDTYPE_KEYHASH = 2;

    /**
     * Algorithm used by server to generate signature on OCSP responses
     */
    public static String getSignatureAlgorithm() {
        return ConfigurationHolder.getString("ocsp.signaturealgorithm");
    }

    /**
     * The interval on which new OCSP signing certificates are loaded in seconds
     */
    public static int getSigningCertsValidTime() {
        int timeInSeconds;
        final int defaultTimeInSeconds = 300; // 5 minutes
        try {
            timeInSeconds = Integer.parseInt(ConfigurationHolder.getString(SIGNING_CERTD_VALID_TIME));
        } catch (NumberFormatException e) {
            timeInSeconds = defaultTimeInSeconds;
            log.warn(SIGNING_CERTD_VALID_TIME + " is not a decimal number. Using default 5 minutes");
        }
        return timeInSeconds * 1000;
    }

    /**
     * If set to true the Servlet will enforce OCSP request signing
     */
    public static boolean getEnforceRequestSigning() {
        String value = ConfigurationHolder.getString(SIGNATUREREQUIRED);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * If set to true the Servlet will restrict OCSP request signing
     */
    public static boolean getRestrictSignatures() {
        String value = ConfigurationHolder.getString("ocsp.restrictsignatures");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * Set this to issuer or signer depending on how you want to restrict allowed signatures for OCSP request signing.
     * 
     * @returns one of OcspConfiguration.RESTRICTONISSUER and OcspConfiguration.RESTRICTONSIGNER
     */
    public static int getRestrictSignaturesByMethod() {
        if ("signer".equalsIgnoreCase(ConfigurationHolder.getString("ocsp.restrictsignaturesbymethod"))) {
            return RESTRICTONSIGNER;
        }
        return RESTRICTONISSUER;
    }

    /**
     * If ocsp.restrictsignatures is true the Servlet will look in this directory for allowed signer certificates or issuers.
     */
    public static String getSignTrustDir() {
        return ConfigurationHolder.getString("ocsp.signtrustdir");
    }

    /**
     * The interval on which list of allowed OCSP request signing certificates are loaded from signTrustDir in seconds.
     */
    public static int getSignTrustValidTimeInSeconds() {
        int result = 180;
        try {
            String configValue = ConfigurationHolder.getString("ocsp.signtrustvalidtime");
            if (configValue != null) {
                result = Integer.parseInt(configValue);
            }
        } catch (NumberFormatException e) {
            log.warn("\"ocsp.signtrustvalidtime\" is not a decimal number. Using default value: " + result);
        }
        return result * 1000;
    }

    /**
     * If set to true the certificate chain will be returned with the OCSP response.
     */
    public static boolean getIncludeCertChain() {
        String value = ConfigurationHolder.getString("ocsp.includecertchain");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * If set to name the OCSP responses will use the Name ResponseId type, if set to keyhash the KeyHash type will be used.
     * 
     * @returns one of OCSPUtil.RESPONDERIDTYPE_NAME and OCSPUtil.RESPONDERIDTYPE_KEYHASH
     */
    public static int getResponderIdType() {
        if ("name".equalsIgnoreCase(ConfigurationHolder.getString("ocsp.responderidtype"))) {
            return RESPONDERIDTYPE_NAME;
        }
        return RESPONDERIDTYPE_KEYHASH;
    }

    /**
     * If true a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as not revoked.
     */
    public static boolean getNonExistingIsGood() {
        String value = ConfigurationHolder.getString("ocsp.nonexistingisgood");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * Specifies the subject of a certificate which is used to identify the responder which will generate responses when no real CA can be found from
     * the request. This is used to generate 'unknown' responses when a request is received for a certificate that is not signed by any CA on this
     * server.
     */
    public static String getDefaultResponderId() {
        return ConfigurationHolder.getExpandedString("ocsp.defaultresponder");
    }

    /**
     * Specifies OCSP extension OIDs that will result in a call to an extension class, separate multiple entries with ';'.
     * 
     * @return a List<String> of extension OIDs
     */
    public static List<String> getExtensionOids() {
        String value = ConfigurationHolder.getString("ocsp.extensionoid");
        if ("".equals(value)) {
            return new ArrayList<String>();
        }
        return Arrays.asList(value.split(";"));
    }

    /**
     * Specifies classes implementing OCSP extensions matching OIDs in getExtensionOid(), separate multiple entries with ';'.
     * 
     * @return a List<String> of extension classes
     */
    public static List<String> getExtensionClasses() {
        String value = ConfigurationHolder.getString("ocsp.extensionclass");
        if ("".equals(value)) {
            return new ArrayList<String>();
        }
        return Arrays.asList(value.split(";"));
    }

    /**
     * DataSource for Unid-Fnr mapping OCSP extension.
     */
    public static String getUnidDataSource() {
        return ConfigurationHolder.getString("ocsp.uniddatsource");
    }

    /**
     * Directory containing certificates of trusted entities allowed to query for Fnrs.
     */
    public static String getUnidTrustDir() {
        return ConfigurationHolder.getString("ocsp.unidtrustdir");
    }

    /**
     * File containing the CA-certificate, in PEM format, that signed the trusted clients.
     */
    public static String getUnidCaCert() {
        return ConfigurationHolder.getString("ocsp.unidcacert");
    }

    /**
     * When true, an audit log will be created.
     */
    public static boolean getAuditLog() {
        String value = ConfigurationHolder.getString("ocsp.audit-log");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * A format string for logging of dates in auditLog and accountLog.
     */
    public static String getLogDateFormat() {
        return ConfigurationHolder.getString("ocsp.log-date");
    }

    /**
     * A format string for TimeZone auditLog and accountLog.
     */
    public static String getLogTimeZone() {
        return ConfigurationHolder.getString("ocsp.log-timezone");
    }

    /**
     * Set to true if you want transactions to be aborted when logging fails.
     */
    public static boolean getLogSafer() {
        String value = ConfigurationHolder.getString("ocsp.log-safer");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * A String to create a java Pattern to format the audit Log
     */
    public static String getAuditLogPattern() {
        return ConfigurationHolder.getString("ocsp.audit-log-pattern");
    }

    /**
     * A String which combined with auditLogPattern determines how auditLog output is formatted.
     */
    public static String getAuditLogOrder() {
        String value = ConfigurationHolder.getString("ocsp.audit-log-order");
        value = value.replace("\\\"", "\""); // From EJBCA 3.9 the "-char does not need to be escaped, but we want to be backward compatible
        return value;
    }

    /**
     * Parameter specifying database test query string. Used to check that the database is operational.
     */
    public static String getHealthCheckDbQuery() {
        return ConfigurationHolder.getExpandedString("ocsphealthcheck.dbquery");
    }

    /**
     * All available signing keys should be tested.
     */
    public static boolean getHealthCheckSignTest() {
        return ConfigurationHolder.getString("ocsphealthcheck.signtest").toLowerCase().indexOf("false") < 0;
    }

    /**
     * @return true if the validity of the OCSP signing certificates should be tested by the healthcheck.
     */
    public static boolean getHealthCheckCertificateValidity() {
        return ConfigurationHolder.getString("ocsphealthcheck.checkSigningCertificateValidity").toLowerCase().indexOf("false") < 0;
    }

    /**
     * When true, a transaction log will be created.
     */
    public static boolean getTransactionLog() {
        String value = ConfigurationHolder.getString("ocsp.trx-log");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * A String to create a java Pattern to format the transaction Log.
     */
    public static String getTransactionLogPattern() {
        return ConfigurationHolder.getString("ocsp.trx-log-pattern");
    }

    /**
     * A String which combined with transactionLogPattern determines how transaction Log output is formatted.
     */
    public static String getTransactionLogOrder() {
        String value = ConfigurationHolder.getString("ocsp.trx-log-order");
        value = value.replace("\\\"", "\""); // From EJBCA 3.9 the "-char does not need to be escaped, but we want to be backward compatible
        return value;
    }

    /**
     * The default number of milliseconds a response is valid, or 0 to disable. See RFC5019.
     */
    public static long getUntilNextUpdate(int certProfileId) {
        long value = 0;
        Configuration config = ConfigurationHolder.instance();
        String key = "ocsp." + certProfileId + ".untilNextUpdate";
        if ((certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) || (!config.containsKey(key))) {
            key = "ocsp.untilNextUpdate";
        }
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            log.warn("\"ocsp.untilNextUpdate\" is not a decimal number. Using default value: " + value);
        }
        return value;
    }

    /**
     * The default number of milliseconds a HTTP-response should be cached. See RFC5019.
     */
    public static long getMaxAge(int certProfileId) {
        long value = 30;
        Configuration config = ConfigurationHolder.instance();
        String key = "ocsp." + certProfileId + ".maxAge";
        if ((certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) || (!config.containsKey(key))) {
            key = "ocsp.maxAge";
        }
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            // Convert default value to milliseconds
            value = value * 1000;
            log.warn("\"ocsp.maxAge\" is not a decimal number. Using default value: " + value);
        }
        return value;
    }

    // Values for stand-alone OCSP

    /**
     * Directory name of the soft keystores. The signing keys will be fetched from all files in this directory. Valid formats of the files are JKS and
     * PKCS12 (p12)."
     */
    public static String getSoftKeyDirectoryName() {
        return ConfigurationHolder.getString(OCSP_KEYS_DIR);
    }

    /**
     * The password for the all the soft keys of the OCSP responder.
     * 
     * @return {@link #getStorePassword()} if property isn't set.
     */
    public static String getKeyPassword() {
        final String value = ConfigurationHolder.getString("ocsp.keys.keyPassword");
        if (value != null) {
            return value;
        }
        return getStorePassword();
    }

    /**
     * The password to all soft keystores.
     * 
     * @return the value of getKeyPassword() if property isn't set.
     */
    public static String getStorePassword() {
        return ConfigurationHolder.getString(STORE_PASSWORD);
    }

    /**
     * The password for all keys stored on card.
     */
    public static String getCardPassword() {
        return ConfigurationHolder.getString(CARD_PASSWORD);
    }

    /**
     * The class that implements card signing of the OCSP response.
     */
    public static String getHardTokenClassName() {
        return ConfigurationHolder.getString("ocsp.hardToken.className");
    }

    /**
     * @return Sun P11 configuration file name.
     */
    public static String getSunP11ConfigurationFile() {
        return ConfigurationHolder.getString("ocsp.p11.sunConfigurationFile");
    }

    /**
     * @return time before the experation of the OCSP signing cert that the signing key should be renewed.
     */
    public static int getRenewTimeBeforeCertExpiresInSeconds() {
        final String sValue = ConfigurationHolder.getString(RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS);
        if (sValue == null || sValue.length() < 1) {
            return -1;
        }
        try {
            return Integer.parseInt(sValue);
        } catch (NumberFormatException e) {
            log.error("Could not parse value of " + RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS + " to integer.", e);
        }
        return -1;
    }

    /**
     * @return EJBCA web service URL
     */
    public static String getEjbcawsracliUrl() {
        return ConfigurationHolder.getString(REKEYING_WSURL);
    }

    /**
     * P11 shared library path name.
     * 
     * @return The value;
     */
    public static String getP11SharedLibrary() {
        return ConfigurationHolder.getString("ocsp.p11.sharedLibrary");
    }

    /**
     * P11 password.
     * 
     * @return The value
     */
    public static String getP11Password() {
        return ConfigurationHolder.getString(P11_PASSWORD);
    }

    /**
     * P11 slot number.
     * 
     * @return The value.
     */
    public static String getP11SlotIndex() {
        return ConfigurationHolder.getString("ocsp.p11.slot");
    }

    /**
     * Should passwords be stored in memory.
     * 
     * Default value is true.
     * 
     * @return True if password should not be stored in memory.
     */
    public static boolean getDoNotStorePasswordsInMemory() {
        final String s = ConfigurationHolder.getString(DO_NOT_STORE_PASSWORDS_IN_MEMORY);
        if (s == null || s.toLowerCase().indexOf("false") >= 0 || s.toLowerCase().indexOf("no") >= 0) {
            return false;
        }
        return true;
    }

    /**
     * Path of the file to be used as SW keystore for the client certificate in the WS session when rekeying.
     * 
     * @return null if SW keystore should not be used.
     */
    public static String getWsSwKeystorePath() {
        return ConfigurationHolder.getString(WSSWKEYSTOREPATH);
    }

    /**
     * @return password for the SW keystore
     */
    public static String getWsSwKeystorePassword() {
        return ConfigurationHolder.getString(WSSWKEYSTOREPASSWORD);
    }

    /**
     * @return alias for keys that could be used as signer keys. null means all keys
     */
    public static String[] getKeyAlias() {
        final String sConf = ConfigurationHolder.getString("ocsp.rekeying.listOfAliases");
        if (sConf == null) {
            return null;
        }
        return StringUtils.split(sConf.trim(), ';');
    }

    /**
     * @return The interval on which new OCSP signing certificates are loaded in seconds
     */
    public static long getWarningBeforeExpirationTime() {
        int timeInSeconds = 0;
        final int defaultTimeInSeconds = 604800; // 1 week 60*60*24*7
        try {
            String configValue = ConfigurationHolder.getString(WARNING_BEFORE_EXPERATION_TIME);
            if (configValue != null) {
                timeInSeconds = Integer.parseInt(configValue);
            } else {
                timeInSeconds = defaultTimeInSeconds;
            }

        } catch (NumberFormatException e) {
            timeInSeconds = defaultTimeInSeconds;
            log.warn(WARNING_BEFORE_EXPERATION_TIME + " is not a decimal number. Using default 1 week.");
        }
        return 1000 * (long) timeInSeconds;
    }

    public static boolean isStandAlone() {
        return ConfigurationHolder.getString("ocsp.isstandalone").equals("true");
    }
}
