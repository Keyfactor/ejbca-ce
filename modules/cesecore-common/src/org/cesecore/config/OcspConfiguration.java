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

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.ex.ConversionException;
import org.apache.log4j.Logger;

/**
 * Parses configuration bundled in conf/ocsp.properties, both for the internal and external OCSP responder.
 * 
 */
public class OcspConfiguration {

    private static final Logger log = Logger.getLogger(OcspConfiguration.class);

    @Deprecated(since = "9.4.0")
    public static final String SIGNING_CERTD_VALID_TIME = "ocsp.signingCertsValidTime";
    @Deprecated(since = "9.4.0")
    public static final String REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME = "ocsp.reqsigncertrevcachetime";
    public static final String SIGNING_TRUSTSTORE_VALID_TIME = "ocsp.signtrustvalidtime";
    public static final String SIGNATUREREQUIRED = "ocsp.signaturerequired";
    public static final String CARD_PASSWORD = "ocsp.keys.cardPassword";
    public static final String WARNING_BEFORE_EXPERATION_TIME = "ocsp.warningBeforeExpirationTime";
    @Deprecated(since = "9.4.0")
    public static final String NON_EXISTING_IS_GOOD = "ocsp.nonexistingisgood";
    public static final String NON_EXISTING_IS_GOOD_URI = NON_EXISTING_IS_GOOD+".uri.";
    public static final String NON_EXISTING_IS_BAD_URI = "ocsp.nonexistingisbad.uri.";
    @Deprecated(since = "9.4.0")
    public static final String NON_EXISTING_IS_REVOKED = "ocsp.nonexistingisrevoked";
    public static final String NON_EXISTING_IS_REVOKED_URI = NON_EXISTING_IS_REVOKED+".uri.";
    @Deprecated(since = "9.4.0")
    public static final String NON_EXISTING_IS_UNAUTHORIZED = "ocsp.nonexistingisunauthorized";

    @Deprecated(since = "8.3.0") //Only used for upgrades to 8.3.0 and beyond
    private static final String UNTIL_NEXT_UPDATE = "ocsp.untilNextUpdate";
    @Deprecated(since = "8.3.0") //Only used for upgrades to 8.3.0 and beyond
    private static final String MAX_AGE = "ocsp.maxAge";
    @Deprecated(since = "8.3.0") //Only used for upgrades to 8.3.0 and beyond
    private static final String CACHE_HEADER_MAX_AGE = "ocsp.expires.useMaxAge";

    @Deprecated(since = "9.4.0") //only used to allow for upgrades to 9.4.0
    public static final String INCLUDE_SIGNING_CERT = "ocsp.includesignercert";
    @Deprecated(since = "9.4.0") //only used to allow for upgrades to 9.4.0
    public static final String INCLUDE_CERT_CHAIN = "ocsp.includecertchain";
        
    /**
     * The interval on which new OCSP signing certificates are loaded in milliseconds
     */
    @Deprecated(since = "9.4.0")
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
    @Deprecated(since = "9.4.0")
    public static long getRequestSigningCertRevocationCacheTimeMs() {
        long timeInMilliseconds;
        final long defaultTimeInMilliseconds = 60*1000L; // 1 minute
        try {
            timeInMilliseconds = Long.parseLong(ConfigurationHolder.getString(REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME));
        } catch (NumberFormatException e) {
            timeInMilliseconds = defaultTimeInMilliseconds;
            log.warn(REQUEST_SIGNING_CERT_REVOCATION_CACHE_TIME + " is not a decimal long. Using default "+defaultTimeInMilliseconds+" ms.");
        }
        return timeInMilliseconds;
    }

    /**
     * If set to true the responder will enforce OCSP request signing
     */
    public static boolean getEnforceRequestSigning() {
        String value = ConfigurationHolder.getString(SIGNATUREREQUIRED);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * If set to true the certificate chain will be returned with the OCSP response.
     * 
     * @deprecated only remains for upgrades to 9.4.0 – use value from GlobalOcspConfiguration
     */
    public static boolean getIncludeCertChain() {
        String value = ConfigurationHolder.getString(INCLUDE_CERT_CHAIN);
        if(value == null) {
            return true; //Default value is true
        }      
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }
    
    /**
     * If set to true the signature certificate will be included the OCSP response.
     * 
     * @deprecated only remains for upgrades to 9.4.0 – use value from GlobalOcspConfiguration
     */
    @Deprecated(since = "9.4.0")
    public static boolean getIncludeSignCert() {
        String value = ConfigurationHolder.getString(INCLUDE_SIGNING_CERT);
        if(value == null) {
            return true; //Default value is true
        }
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * @return true if a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as not revoked.
     */
    @Deprecated(since = "9.4.0")
    public static boolean getNonExistingIsGood() {
        String value = ConfigurationHolder.getString(NON_EXISTING_IS_GOOD);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }
    
    /**
     * @return true if a certificate that does not exist in the database, but is issued by a CA the responder handles will be treated as revoked.
     */
    @Deprecated(since = "9.4.0")
    public static boolean getNonExistingIsRevoked() {
        String value = ConfigurationHolder.getString(NON_EXISTING_IS_REVOKED);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }
    
    /**
     * 
     * @return true if a certificate that does not exist in the database, but is issued by a CA the responder handles will be responded to with an
     * unsigned "Unauthorized" response. 
     */
    @Deprecated(since = "9.4.0")
    public static boolean getNonExistingIsUnauthorized() {
        String value = ConfigurationHolder.getString(NON_EXISTING_IS_UNAUTHORIZED);
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
    public static String getNonExistingIsGoodOverrideRegex() {
    	return getRegex(NON_EXISTING_IS_GOOD_URI);
    }

    /**
     * Calls from client fulfilling this regex returns "not existing" for non existing certificates
     * even if {@link #getNonExistingIsGood()} return true.
     * @return the regex
     */
    public static String getNonExistingIsBadOverrideRegex() {
    	return getRegex(NON_EXISTING_IS_BAD_URI);
    }
    
    /**
     * Calls from client fulfilling this regex returns "revoked" for non existing certificates
     * even if {@link #getNonExistingIsGood()} return true.
     * @return the regex
     */
    public static String getNonExistingIsRevokedOverrideRegex() {
        return getRegex(NON_EXISTING_IS_REVOKED_URI);
    }
    
    /**
     * @return true if UnidFnr is enabled in ocsp.properties
     */
    public static boolean isUnidEnabled() {
        if (ConfigurationHolder.getString("unidfnr.enabled") != null && ConfigurationHolder.getString("unidfnr.enabled").equals("true")) {
            return true;
        }
        return false;
    }

    /**
     * All available signing keys should be tested.
     */
    public static boolean getHealthCheckSignTest() {
        return !ConfigurationHolder.getString("ocsphealthcheck.signtest").toLowerCase().contains("false");
    }

    /**
     * @return true if the validity of the OCSP signing certificates should be tested by the healthcheck.
     */
    public static boolean getHealthCheckCertificateValidity() {
        return !ConfigurationHolder.getString("ocsphealthcheck.checkSigningCertificateValidity").toLowerCase().contains("false");
    }

    public static boolean getLogSafer() {
        final String value = ConfigurationHolder.getString("ocsp.log-safer");
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }
    
    /**
     * The default number of milliseconds a response is valid, or 0 to disable. See RFC5019.
     * 
     * @deprecated Do not use with CertificateProfileConstants.CERTPROFILE_NO_PROFILE, since the global value has been moved to the database. Only used for upgrades to 8.3 and beyond.
     */
    @Deprecated
    public static long getUntilNextUpdate() {
        long value = 0;
        Configuration config = ConfigurationHolder.instance();
        final String key = UNTIL_NEXT_UPDATE;
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            log.warn("\"ocsp.untilNextUpdate\" is not a decimal integer. Using default value: " + value);
        }
        return value;
    }

    /**
     * @return true if "Expires" header should be based on max-age rather than nextUpdate (violates RFC 5019)
     * 
     * @deprecated Configuration moved to database. Only used for upgrades to 8.3 and beyond.
     */
    @Deprecated
    public static boolean getCacheHeaderMaxAge() {
        String value = ConfigurationHolder.getString(CACHE_HEADER_MAX_AGE);
        return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
    }

    /**
     * The default number of milliseconds a HTTP-response should be cached. See RFC5019.
     * 
     * @deprecated Do not use with CertificateProfileConstants.CERTPROFILE_NO_PROFILE, since the global value has been moved to the database. Only used for upgrades to 8.3 and beyond.
     */
    @Deprecated
    public static long getMaxAge() {
        long value = 30;
        Configuration config = ConfigurationHolder.instance();
        final String key = MAX_AGE;
        try {
            value = (config.getLong(key, value) * 1000);
        } catch (ConversionException e) {
            // Convert default value to milliseconds
            value = value * 1000;
            log.warn("\"ocsp.maxAge\" is not a decimal integer. Using default value: " + value);
        }
        return value;
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
