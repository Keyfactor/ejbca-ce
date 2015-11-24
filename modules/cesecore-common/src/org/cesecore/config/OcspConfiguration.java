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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.util.CertTools;

/**
 * Parses configuration bundled in conf/ocsp.properties, both for the internal and external OCSP responder.
 * 
 * @version $Id$
 */
public class OcspConfiguration {

    private static final Logger log = Logger.getLogger(OcspConfiguration.class);

    @Deprecated // Deprecated in 6.2.4, remains to allow migration from previous versions
    public static final String DEFAULT_RESPONDER = "ocsp.defaultresponder";
    public static final String SIGNING_CERTD_VALID_TIME = "ocsp.signingCertsValidTime";
    public static final String REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME = "ocsp.reqsigncertrevcachetime";
    public static final String SIGNING_TRUSTSTORE_VALID_TIME = "ocsp.signtrustvalidtime";
    public static final String SIGNATUREREQUIRED = "ocsp.signaturerequired";
    public static final String CARD_PASSWORD = "ocsp.keys.cardPassword";
    public static final String REKEYING_WSURL = "ocsp.rekeying.wsurl";
    public static final String WARNING_BEFORE_EXPERATION_TIME = "ocsp.warningBeforeExpirationTime";
    public static final String NONE_EXISTING_IS_GOOD = "ocsp.nonexistingisgood";
    public static final String NONE_EXISTING_IS_GOOD_URI = NONE_EXISTING_IS_GOOD+".uri.";
    public static final String NONE_EXISTING_IS_BAD_URI = "ocsp.nonexistingisbad.uri.";
    public static final String NONE_EXISTING_IS_REVOKED = "ocsp.nonexistingisrevoked";
    public static final String NONE_EXISTING_IS_REVOKED_URI = NONE_EXISTING_IS_REVOKED+".uri.";
    public static final String REKEYING_TRIGGERING_HOSTS =  "ocsp.rekeying.trigging.hosts";
    public static final String REKEYING_TRIGGERING_PASSWORD = "ocsp.rekeying.trigging.password";
    public static final String REKEYING_UPDATE_TIME_IN_SECONDS = "ocsp.rekeying.update.time.in.seconds";
    public static final String REKEYING_SAFETY_MARGIN_IN_SECONDS = "ocsp.rekeying.safety.margin.in.seconds";
    public static final String EXPIREDCERT_RETENTIONPERIOD = "ocsp.expiredcert.retentionperiod";
    public static final String UNTIL_NEXT_UPDATE = "ocsp.untilNextUpdate";
    public static final String REVOKED_UNTIL_NEXT_UPDATE = "ocsp.revoked.untilNextUpdate";
    public static final String MAX_AGE = "ocsp.maxAge";
    public static final String REVOKED_MAX_AGE = "ocsp.revoked.maxAge";
    public static final String INCLUDE_SIGNING_CERT = "ocsp.includesignercert";
    public static final String INCLUDE_CERT_CHAIN = "ocsp.includecertchain";
    public static final String RESPONDER_ID_TYPE = "ocsp.responderidtype";
    
    @Deprecated //Remove this value once upgrading VAs to EJBCA 6 has been dropped
    public static final int RESTRICTONISSUER = 0;
    @Deprecated //Remove this value once upgrading VAs to EJBCA 6 has been dropped
    public static final int RESTRICTONSIGNER = 1;

    public static final int RESPONDERIDTYPE_NAME = 1;
    public static final int RESPONDERIDTYPE_KEYHASH = 2;

    public static Set<String> acceptedSignatureAlgorithms = new HashSet<String>();
    
    /**
     * Algorithm used by server to generate signature on OCSP responses
     */
    public static String getSignatureAlgorithm() {
        return ConfigurationHolder.getString("ocsp.signaturealgorithm");
    }

    /**
     * Returns if the specified signature algorithm is among the signature algorithms accepted by EJBCA.
     * 
     * The signatures algorithms that are accepted by EJBCA are specified in 'ocsp.signaturealgorithm' in the 
     * EJBCA_HOME/conf/ocsp.properties file.
     * 
     * @param sigAlg
     * @return 'true' if sigAlg is accepted by EJBCA, and 'false' otherwise
     */
    public static boolean isAcceptedSignatureAlgorithm(String sigAlg) {
        if(acceptedSignatureAlgorithms.size() == 0) {
            String[] algs = getSignatureAlgorithm().split(";");
            for(String alg : algs) {
                acceptedSignatureAlgorithms.add(alg);
            }
        }
        return acceptedSignatureAlgorithms.contains(sigAlg);
    }

    /**
     * 
     * @return How often the standalone OCSP certificate cache should be checked for expiring certificates. Default value i 1 hour
     */
    public static long getRekeyingUpdateTimeInSeconds() {
        return Long.parseLong(ConfigurationHolder.getString(REKEYING_UPDATE_TIME_IN_SECONDS));
    }
    
    /**
     * 
     * @return How long from true expiry time that a certificate should be renewed. Default value is 1 day
     */
    public static long getRekeyingSafetyMarginInSeconds() {
        return Long.parseLong(ConfigurationHolder.getString(REKEYING_SAFETY_MARGIN_IN_SECONDS));
    }
    
    /**
     * The interval on which new OCSP signing certificates are loaded in milliseconds
     */
    public static int getSigningCertsValidTimeInMilliseconds() {
        int timeInSeconds;
        final int defaultTimeInSeconds = 300; // 5 minutes
        try {
            timeInSeconds = Integer.parseInt(ConfigurationHolder.getString(SIGNING_CERTD_VALID_TIME));
        } catch (NumberFormatException e) {
            timeInSeconds = defaultTimeInSeconds;
            log.warn(SIGNING_CERTD_VALID_TIME + " is not a decimal integer. Using default 5 minutes");
        }
        return timeInSeconds*1000;
    }

    /**
     * The interval on which new OCSP signing certificates are loaded in milliseconds
     */
    public static long getRequestSigningCertRevocationCacheTimeMs() {
        long timeInSeconds;
        final long defaultTimeInSeconds = 60*1000L; // 1 minute
        try {
            timeInSeconds = Long.parseLong(ConfigurationHolder.getString(REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME));
        } catch (NumberFormatException e) {
            timeInSeconds = defaultTimeInSeconds;
            log.warn(REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME + " is not a decimal long. Using default "+defaultTimeInSeconds+" ms.");
        }
        return timeInSeconds;
    }

    /**
     * If set to true the responder will enforce OCSP request signing
     */
    public static boolean getEnforceRequestSigning() {
        String value = ConfigurationHolder.getString(SIGNATUREREQUIRED);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * If set to true the responder will restrict OCSP request signing
     */
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static boolean getRestrictSignatures() {
        String value = ConfigurationHolder.getString("ocsp.restrictsignatures");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * Set this to issuer or signer depending on how you want to restrict allowed signatures for OCSP request signing.
     * 
     * @returns one of OcspConfiguration.RESTRICTONISSUER and OcspConfiguration.RESTRICTONSIGNER
     */
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static int getRestrictSignaturesByMethod() {
        if ("signer".equalsIgnoreCase(ConfigurationHolder.getString("ocsp.restrictsignaturesbymethod"))) {
            return RESTRICTONSIGNER;
        }
        return RESTRICTONISSUER;
    }

    /**
     * If ocsp.restrictsignatures is true the Servlet will look in this directory for allowed signer certificates or issuers.
     */
    @Deprecated //Remove this value once upgrading VAs to EJBCA 6 has been dropped
    public static String getSignTrustDir() {
        return ConfigurationHolder.getString("ocsp.signtrustdir");
    }

    /**
     * If set to true the certificate chain will be returned with the OCSP response.
     */
    public static boolean getIncludeCertChain() {
        String value = ConfigurationHolder.getString(INCLUDE_CERT_CHAIN);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }
    
    /**
     * If set to true the signature certificate will be included the OCSP response.
     */
    public static boolean getIncludeSignCert() {
        String value = ConfigurationHolder.getString(INCLUDE_SIGNING_CERT);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * If set to name the OCSP responses will use the Name ResponseId type, if set to keyhash the KeyHash type will be used.
     * 
     * @returns one of OCSPUtil.RESPONDERIDTYPE_NAME and OCSPUtil.RESPONDERIDTYPE_KEYHASH
     */
    public static int getResponderIdType() {
        if ("name".equalsIgnoreCase(ConfigurationHolder.getString(RESPONDER_ID_TYPE))) {
            return RESPONDERIDTYPE_NAME;
        }
        return RESPONDERIDTYPE_KEYHASH;
    }

    /**
     * If true a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as not revoked.
     */
    public static boolean getNonExistingIsGood() {
        String value = ConfigurationHolder.getString(NONE_EXISTING_IS_GOOD);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }
    
    /**
     * If true a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as revoked.
     */
    public static boolean getNonExistingIsRevoked() {
        String value = ConfigurationHolder.getString(NONE_EXISTING_IS_REVOKED);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    private static String getRegex(String prefix) {
    	int i=1;
    	final StringBuffer regex = new StringBuffer();
    	while( true ) {
    		final String key = prefix+i;
    		final String value = ConfigurationHolder.getString(key);
    		if ( value==null ) {
    			break;
    		}
    		if ( i>1 ) {
    			regex.append('|');
    		}
    		regex.append('(');
    		regex.append(value);
    		regex.append(')');
    		i++;
    	}
    	if ( regex.length()<1 ) {
    		return null;
    	}
    	return regex.toString();
    }

    /**
     * Calls from client fulfilling this regex returns good for non existing certificates
     * even if {@link #getNonExistingIsGood()} return false.
     * @return the regex
     */
    public static String getNonExistingIsGoodOverideRegex() {
    	return getRegex(NONE_EXISTING_IS_GOOD_URI);
    }

    /**
     * Calls from client fulfilling this regex returns "not existing" for non existing certificates
     * even if {@link #getNonExistingIsGood()} return true.
     * @return the regex
     */
    public static String getNonExistingIsBadOverideRegex() {
    	return getRegex(NONE_EXISTING_IS_BAD_URI);
    }
    
    /**
     * Calls from client fulfilling this regex returns "revoked" for non existing certificates
     * even if {@link #getNonExistingIsGood()} return true.
     * @return the regex
     */
    public static String getNonExistingIsRevokedOverideRegex() {
        return getRegex(NONE_EXISTING_IS_REVOKED_URI);
    }

    /**
     * Specifies the subject of a certificate which is used to identify the responder which will generate responses when no real CA can be found from
     * the request. This is used to generate 'unknown' responses when a request is received for a certificate that is not signed by any CA on this
     * server.
     * @return the name configured in ocsp.defaultresponder, reordered to EJBCA normalized ordering.
     * 
     * @deprecated This value is deprecated since 6.2.4, and only remains in order to allow migration. Default responder is now set in global configuration instead. 
     */
    @Deprecated
    public static String getDefaultResponderId() {
        final String ret = ConfigurationHolder.getExpandedString(DEFAULT_RESPONDER);
        if (ret != null) {
            return CertTools.stringToBCDNString(ret);
        }
        return ret;
    }

    /**
     * Specifies OCSP extension OIDs that will result in a call to an extension class, separate multiple entries with ';'.
     * For any entry that should be always used, preface with '*' (e.g. *2.16.578.1.16.3.2)
     * 
     * @return a List<String> of extension OIDs, an empty list if none are found.
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
     * The default number of milliseconds a response is valid, or -1 to disable. See RFC5019.
     */
    public static long getExpiredArchiveCutoff() {
        Configuration config = ConfigurationHolder.instance();
        
        if(StringUtils.equals(config.getString(EXPIREDCERT_RETENTIONPERIOD), "-1")) {
            return -1;
        }
        
        long value = 31536000;
        try {
            value = config.getLong(EXPIREDCERT_RETENTIONPERIOD, value) * 1000;
        } catch (ConversionException e) {
            log.warn("\"ocsp.expiredcert.retentionperiod\" is not a decimal integer. Using default value: " + value);
        }
        
        
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
            key = UNTIL_NEXT_UPDATE;
        }
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            log.warn("\"ocsp.untilNextUpdate\" is not a decimal integer. Using default value: " + value);
        }
        return value;
    }
    
    /** @return true if Until Next Update is explicitly configured for the requested certificate profile */
    public static boolean isUntilNextUpdateConfigured(final int certificateProfileId) {
        if (certificateProfileId==CertificateProfileConstants.CERTPROFILE_NO_PROFILE){
            return ConfigurationHolder.instance().containsKey(UNTIL_NEXT_UPDATE);
        } else {
            return ConfigurationHolder.instance().containsKey("ocsp." + certificateProfileId + ".untilNextUpdate");
        }
    }
    
    /**
     * The default number of milliseconds a response of a revoked certificate is valid, or 0 to disable. See RFC5019.
     */
    public static long getRevokedUntilNextUpdate(int certProfileId) {
        long value = 0;
        Configuration config = ConfigurationHolder.instance();
        String key = "ocsp." + certProfileId + ".revoked.untilNextUpdate";
        if ((certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) || (!config.containsKey(key))) {
            key = REVOKED_UNTIL_NEXT_UPDATE;
        }
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            log.warn("\"ocsp.revoked.untilNextUpdate\" is not a decimal integer. Using default value: " + value);
        }
        return value;
    }
    
    /** @return true if Until Next Update is explicitly configured for the requested certificate profile in case of a revoked certificate */
    public static boolean isRevokedUntilNextUpdateConfigured(final int certificateProfileId) {
        if (certificateProfileId==CertificateProfileConstants.CERTPROFILE_NO_PROFILE){
            return ConfigurationHolder.instance().containsKey(REVOKED_UNTIL_NEXT_UPDATE);
        } else {
            return ConfigurationHolder.instance().containsKey("ocsp." + certificateProfileId + ".revoked.untilNextUpdate");
        }
    }

    /**
     * The default number of milliseconds a HTTP-response should be cached. See RFC5019.
     */
    public static long getMaxAge(int certProfileId) {
        long value = 30;
        Configuration config = ConfigurationHolder.instance();
        String key = "ocsp." + certProfileId + ".maxAge";
        if ((certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) || (!config.containsKey(key))) {
            key = MAX_AGE;
        }
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            // Convert default value to milliseconds
            value = value * 1000;
            log.warn("\"ocsp.maxAge\" is not a decimal integer. Using default value: " + value);
        }
        return value;
    }

    /** @return true if Until Next Update is explicitly configured for the requested certificate profile */
    public static boolean isMaxAgeConfigured(final int certificateProfileId) {
        if (certificateProfileId==CertificateProfileConstants.CERTPROFILE_NO_PROFILE){
            return ConfigurationHolder.instance().containsKey(MAX_AGE);
        } else {
            return ConfigurationHolder.instance().containsKey("ocsp." + certificateProfileId + ".maxAge");
        }
    }
    
    /**
     * The default number of milliseconds a HTTP-response for a revoked certificater should be cached. See RFC5019.
     */
    public static long getRevokedMaxAge(int certProfileId) {
        long value = 30;
        Configuration config = ConfigurationHolder.instance();
        String key = "ocsp." + certProfileId + ".revoked.maxAge";
        if ((certProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) || (!config.containsKey(key))) {
            key = REVOKED_MAX_AGE;
        }
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            // Convert default value to milliseconds
            value = value * 1000;
            log.warn("\"ocsp.revoked.maxAge\" is not a decimal integer. Using default value: " + value);
        }
        return value;
    }

    /** @return true if Until Next Update is explicitly configured for the requested certificate profile in case of a revoked certificate*/
    public static boolean isRevokedMaxAgeConfigured(final int certificateProfileId) {
        if (certificateProfileId==CertificateProfileConstants.CERTPROFILE_NO_PROFILE){
            return ConfigurationHolder.instance().containsKey(REVOKED_MAX_AGE);
        } else {
            return ConfigurationHolder.instance().containsKey("ocsp." + certificateProfileId + ".revoked.maxAge");
        }
    }


    // Values for stand-alone OCSP

    /**
     * Directory name of the soft keystores. The signing keys will be fetched from all files in this directory. Valid formats of the files are JKS and
     * PKCS12 (p12)."
     */
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static String getSoftKeyDirectoryName() {
        return ConfigurationHolder.getString("ocsp.keys.dir");
    }

    /**
     * The password for the all the soft keys of the OCSP responder.
     * 
     * @return {@link #getStorePassword()} if property isn't set.
     */
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
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
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static String getStorePassword() {
        return ConfigurationHolder.getString("ocsp.keys.storePassword");
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
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static String getSunP11ConfigurationFile() {
        return ConfigurationHolder.getString("ocsp.p11.sunConfigurationFile");
    }

    /**
     * Get set of host IPs that are allowed to trigger rekeying.
     * @return the array
     */
    public static Set<String> getRekeyingTriggingHosts() {
        final String sHosts = ConfigurationHolder.getString(REKEYING_TRIGGERING_HOSTS);
        if (sHosts == null) {
            return new HashSet<String>();
        } else {
            return new HashSet<String>(Arrays.asList(StringUtils.split(sHosts.trim(), ';')));
        }
    }
    /**
     * Get password needed for triggering rekey. Null means that it is not possible to trigger rekey.
     * @return the password
     */
    public static String getRekeyingTriggingPassword() {
        return ConfigurationHolder.getString(REKEYING_TRIGGERING_PASSWORD);
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
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static String getP11SharedLibrary() {
        return ConfigurationHolder.getString("ocsp.p11.sharedLibrary");
    }

    /**
     * P11 password.
     * 
     * @return The value
     */
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static String getP11Password() {
        return ConfigurationHolder.getString("ocsp.p11.p11password");
    }

    /**
     * P11 slot number.
     * 
     * @return The value.
     */
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
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
    @Deprecated //Remove this method once upgrading VAs to EJBCA 6 has been dropped
    public static boolean getDoNotStorePasswordsInMemory() {
        final String s = ConfigurationHolder.getString("ocsp.activation.doNotStorePasswordsInMemory");
        if (s == null || s.toLowerCase().indexOf("false") >= 0 || s.toLowerCase().indexOf("no") >= 0) {
            return false;
        }
        return true;
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
            log.warn(WARNING_BEFORE_EXPERATION_TIME + " is not a decimal integer. Using default 1 week.");
        }
        return 1000 * (long) timeInSeconds;
    }

}
