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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

/**
 * This file handles configuration from cesecore.properties
 */
public final class CesecoreConfiguration {

    private static final Logger log = Logger.getLogger(CesecoreConfiguration.class);

    public static final String CUSTOM_CLASS_WHITELIST_KEY = "custom.class.whitelist";
    
    /** NOTE: diff between EJBCA and CESeCore */
    public static final String PERSISTENCE_UNIT = "ejbca";
    public static final String AVAILABLE_CIPHER_SUITES_SPLIT_CHAR = ";";
    public static final String DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA = "20";
    private static final String DEFAULT_SERIAL_NUMBER_OCTET_SIZE_EXISTINGCA = "8";

    /** This is a singleton so it's not allowed to create an instance explicitly */
    private CesecoreConfiguration() {
    }

    private static final String FALSE = "false";

    /**
     * Cesecore Datasource name
     */
    public static String getDataSourceJndiName() {
        String prefix = ConfigurationHolder.getString("datasource.jndi-name-prefix");
        String name = ConfigurationHolder.getString("datasource.jndi-name");

        return prefix + name;
    }

    /**
     * The length in octets of certificate serial numbers generated for legacy CAs. (8 octets is a 64 bit serial number.)
     */
    public static int getSerialNumberOctetSizeForExistingCa() {
        String value = ConfigurationHolder.getConfiguredString("ca.serialnumberoctetsize");
        if (value == null) {
            if (log.isDebugEnabled()) {
                log.debug("Using default value of " + DEFAULT_SERIAL_NUMBER_OCTET_SIZE_EXISTINGCA + " for existing CA's ca.serialnumberoctetsize");
            }
            value = DEFAULT_SERIAL_NUMBER_OCTET_SIZE_EXISTINGCA;
        }
        return Integer.parseInt(value);
    }

    /**
     * The length in octets of certificate serial numbers generated for new CAs.
     */
    public static int getSerialNumberOctetSizeForNewCa() {
        String value = ConfigurationHolder.getConfiguredString("ca.serialnumberoctetsize"); 
        if (value == null) {
            if (log.isDebugEnabled()) {
                log.debug("Using default value of " + DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA + " for new CA's ca.serialnumberoctetsize");
            }
            value = DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA;
        }
        return Integer.parseInt(value);
    }
    
        
    /**
     * The algorithm that should be used to generate random numbers (Random Number Generator Algorithm)
     */
    public static String getCaSerialNumberAlgorithm() {
        return ConfigurationHolder.getString("ca.rngalgorithm");
    }

    /**
     * The relative time offset for the notBefore value of CA and end entity certificates. Changing this value,
     * also changes the notAfter attribute of the certificates, if a relative time is used for its validity. While
     * certificate issuance this value can be overwritten by the corresponding value in the certificate profile used.
     * @see org.cesecore.certificates.certificateprofile.CertificateProfile#getCertificateValidityOffset()
     * @see org.cesecore.util.SimpleTime
     */
    public static String getCertificateValidityOffset() {
        return ConfigurationHolder.getExpandedString("certificate.validityoffset");
    }

    /**
     * The language that should be used internally for logging, exceptions and approval notifications.
     */
    public static String getInternalResourcesPreferredLanguage() {
        return ConfigurationHolder.getExpandedString("intresources.preferredlanguage");
    }

    /**
     * The language used internally if a resource not found in the preferred language
     */
    public static String getInternalResourcesSecondaryLanguage() {
        return ConfigurationHolder.getExpandedString("intresources.secondarylanguage");
    }

    /** Parameter to specify if retrieving CAInfo and CA from CAAdminSession should be cached, and in that case for how long. */
    public static long getCacheCaTimeInCaSession() {
        // Cache for 10 seconds is the default (Changed 2013-02-14 under ECA-2801.)
        return getLongValue("cainfo.cachetime", 10000L, "milliseconds to cache CA info");
    }

    /** @return configuration for when cached CryptoTokens are considered stale and will be refreshed from the database. */
    public static long getCacheTimeCryptoToken() {
        return getLongValue("cryptotoken.cachetime", 10000L, "milliseconds");
    }

    /** @return configuration for when cached SignersMapping are considered stale and will be refreshed from the database. */
    public static long getCacheTimeInternalKeyBinding() {
        return getLongValue("internalkeybinding.cachetime", 10000L, "milliseconds");
    }

    /** Parameter to specify if retrieving Certificate profiles in StoreSession should be cached, and in that case for how long. */
    public static long getCacheCertificateProfileTime() {
        return getLongValue("certprofiles.cachetime", 1000L, "milliseconds to cache Certificate profiles");
    }

    /**
     * Parameter to specify if retrieving GlobalOcspConfiguration (in GlobalConfigurationSessionBean) should be cached, and in that case for how long.
     */
    public static long getCacheGlobalOcspConfigurationTime() {
        return getLongValue("ocspconfigurationcache.cachetime", 30000, "milliseconds to cache OCSP settings");
    }

    /**
     * Parameter to specify if retrieving PublicKeyBlacklist objects from PublicKeyBlacklistSession should be cached, and in that case for how long.
     */
    public static long getCachePublicKeyBlacklistTime() {
        return getLongValue("blacklist.cachetime", 30000L, "milliseconds to cache public key block list entries");
    }

    /**
     * Parameter to specify if retrieving KeyValidator objects from KeyValidatorSession should be cached, and in that case for how long.
     */
    public static long getCacheKeyValidatorTime() {
        return getLongValue("validator.cachetime", 30000L, "milliseconds to cache validators");
    }

    /** Parameter to specify if retrieving Authorization Access Rules (in AuthorizationSession) should be cached, and in that case for how long. */
    public static long getCacheAuthorizationTime() {
        return getLongValue("authorization.cachetime", 30000L, "milliseconds to cache authorization");
    }

    /**
     * Parameter to specify if retrieving GlobalConfiguration (in GlobalConfigurationSessionBean) should be cached, and in that case for how long.
     */
    public static long getCacheGlobalConfigurationTime() {
        return getLongValue("globalconfiguration.cachetime", 30000L, "milliseconds to cache authorization");
    }

    private static long getLongValue(final String propertyName, final long defaultValue, final String unit) {
        final String value = ConfigurationHolder.getString(propertyName);
        long time = defaultValue;
        try {
            if (value != null) {
                time = Long.parseLong(value);
            }
        } catch (NumberFormatException e) {
            log.error("Invalid value for " + propertyName + ". Using default " + defaultValue + ". Value must be decimal number (" + unit + "): " + e.getMessage());
        }
        return time;
    }

    public static Class<?> getTrustedTimeProvider() throws ClassNotFoundException {
        String providerClass = ConfigurationHolder.getString("time.provider");
        if(log.isDebugEnabled()) {
            log.debug("TrustedTimeProvider class: "+providerClass);
        }
        return Class.forName(providerClass);
    }

    /**
     * Regular Expression to fetch the NTP offset from an NTP client output
     */
    public static Pattern getTrustedTimeNtpPattern() {
        String regex = ConfigurationHolder.getString("time.ntp.pattern");
        return Pattern.compile(regex);
    }

    /**
     * System command to execute an NTP client call and obtain information about the selected peers and their offsets
     */
    public static String getTrustedTimeNtpCommand() {
        return ConfigurationHolder.getString("time.ntp.command");
    }

    /**
     * When we run in a cluster, each node should have it's own identifier. By default we use the DNS name.
     */
    public static String getNodeIdentifier() {
    	final String PROPERTY_NAME = "cluster.nodeid";
    	final String PROPERTY_VALUE = "undefined";
        String value = ConfigurationHolder.getString(PROPERTY_NAME);
        if (value == null) {
        	try {
				value = InetAddress.getLocalHost().getHostName();
			} catch (UnknownHostException e) {
				log.warn(PROPERTY_NAME + " is undefined on this host and was not able to resolve hostname. Using " + PROPERTY_VALUE + " which is fine if use a single node.");
				value = PROPERTY_VALUE;
			}
			// Update configuration, so we don't have to make a hostname lookup each time we call this method.
            ConfigurationHolder.updateConfigurationWithoutBackup(PROPERTY_NAME, value);
        }
        return value;
    }

    /**
     * @return true if the Base64CertData table should be used for storing the certificates.
     */
    public static boolean useBase64CertTable() {
        final String value = ConfigurationHolder.getString("database.useSeparateCertificateTable");
        return value!=null && Boolean.parseBoolean(value.trim());
    }

    /** If database integrity protection should be used or not. */
    public static boolean useDatabaseIntegrityProtection(final String tableName) {
        // First check if we have explicit configuration for this entity
        final String enableProtect = ConfigurationHolder.getString("databaseprotection.enablesign." + tableName);
        if (enableProtect != null) {
            return Boolean.TRUE.toString().equalsIgnoreCase(enableProtect);
        }
        // Otherwise use the global or default
        return Boolean.TRUE.toString().equalsIgnoreCase(ConfigurationHolder.getString("databaseprotection.enablesign"));
    }

    /** If database integrity verification should be used or not. */
    public static boolean useDatabaseIntegrityVerification(final String tableName) {
        // First check if we have explicit configuration for this entity
        final String enableVerify = ConfigurationHolder.getString("databaseprotection.enableverify." + tableName);
        if (enableVerify != null) {
            return Boolean.TRUE.toString().equalsIgnoreCase(enableVerify);
        }
        // Otherwise use the global or default
        return Boolean.TRUE.toString().equalsIgnoreCase(ConfigurationHolder.getString("databaseprotection.enableverify"));
    }

    /** @return the number of rows that should be fetched at the time when creating CRLs. */
    public static int getDatabaseRevokedCertInfoFetchSize() {
        return (int) getLongValue("database.crlgenfetchsize", 500000L, "rows");
    }

    /**
     * Whether EJBCA should request ordered fetching of revoked certificates when generating CRLs.
     * This is a workaround for MS-SQL.
     */
    public static boolean getDatabaseRevokedCertInfoFetchOrdered() {
        return Boolean.TRUE.toString().equalsIgnoreCase(ConfigurationHolder.getString("database.crlgenfetchordered"));
    }

    /**
     * Gets the maximum number of entries in the CT cache. Each entry contains the SCTs for a
     * given certificate. Each SCT will be around 100-150 bytes, and a certificate will typically
     * have 2-4 SCTs. Also, the cache may temporarily overshoot by 50%. There's also some overhead
     * for the cache data structure (ConcurrentCache).
     *
     * -1 means no limit (and not "off"). The default is 100 000.
     *
     * @see #getCTCacheEnabled
     */
    public static long getCTCacheMaxEntries() {
        return getLongValue("ct.cache.maxentries", 100000L, "number of entries in cache");
    }

    /**
     * How many milliseconds between periodic cache cleanup. The cleanup routine is only
     * run when the cache is filled with too many entries.
     */
    public static long getCTCacheCleanupInterval() {
        return getLongValue("ct.cache.cleanupinterval", 10000L, "milliseconds between periodic cache cleanup");
    }

    /** Whether caching of SCTs should be enabled. The default is true. */
    public static boolean getCTCacheEnabled() {
        final String value = ConfigurationHolder.getString("ct.cache.enabled");
        return value == null || !value.trim().equalsIgnoreCase(FALSE);
    }

    /**
     * Whether log availability should be tracked, and requests should "fast fail"
     * whenever a log is known to be down. A log is "known to be down" when it
     * is either unreachable or responds with an HTTP error status to a request.
     */
    public static boolean getCTFastFailEnabled() {
        final String value = ConfigurationHolder.getString("ct.fastfail.enabled");
        return value == null || !value.trim().equalsIgnoreCase(FALSE);
    }

    /**
     * How long time (in milliseconds) EJBCA should wait until trying to use a log
     * which has failed to respond to a request.
     */
    public static long getCTFastFailBackOff() {
        return getLongValue("ct.fastfail.backoff", 1000L, "milliseconds");
    }
    
    /**
     * 
     * @return a list of custom classes allowed to be deserialized by cesecore.properties
     */
    public static String getCustomClassWhitelist() {
        final String customClassWhitelist = ConfigurationHolder.getExpandedString(CUSTOM_CLASS_WHITELIST_KEY);
        return (customClassWhitelist != null ? customClassWhitelist : "");
    }

}
