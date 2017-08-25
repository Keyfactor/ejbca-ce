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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * This file handles configuration from ejbca.properties
 * 
 * @version $Id$
 */
public final class EjbcaConfiguration {

    private static final Logger log = Logger.getLogger(EjbcaConfiguration.class);

    // This is a singleton with on static methods
    private EjbcaConfiguration() {
    }

    private static final String TRUE = "true";

    /**
     * Check if EJBCA is running in production
     */
    public static boolean getIsInProductionMode() {
        final String value = EjbcaConfigurationHolder.getString("ejbca.productionmode");
        if (TRUE.equalsIgnoreCase(value) || "ca".equalsIgnoreCase(value) || "ocsp".equalsIgnoreCase(value)) {
            return true;
        }
        return false;
    }

    /**
     * Password used to protect CMS keystores in the database.
     */
    public static String getCaCmsKeyStorePass() {
        return EjbcaConfigurationHolder.getExpandedString("ca.cmskeystorepass");
    }

    /**
     * How long an request should stay valid. The value is stored in seconds in the configuration, but returned as milliseconds.
     */
    public static long getApprovalDefaultRequestValidity() {
        long value = 28800L;
        try {
            value = Long.parseLong(EjbcaConfigurationHolder.getString("approval.defaultrequestvalidity"));
        } catch (NumberFormatException e) {
            log.warn("\"approval.defaultrequestvalidity\" is not a decimal number. Using default value: " + value);
        }
        return value * 1000L;
    }

    /**
     * How long an approved request should stay valid. The value is stored in seconds in the configuration, but returned as milliseconds.
     */
    public static long getApprovalDefaultApprovalValidity() {
        long value = 28800L;
        try {
            value = Long.parseLong(EjbcaConfigurationHolder.getString("approval.defaultapprovalvalidity"));
        } catch (NumberFormatException e) {
            log.warn("\"approval.defaultapprovalvalidity\" is not a decimal number. Using default value: " + value);
        }
        return value * 1000L;
    }
    
    /**
     * How long time an administrator can extend an approval request for, or 0 to forbid extension of request expiration time.
     * The value is stored in seconds in the configuration, but returned as milliseconds.
     */
    public static long getApprovalDefaultMaxExtensionTime() {
        long value = 0L;
        try {
            value = Long.parseLong(EjbcaConfigurationHolder.getString("approval.defaultmaxextensiontime"));
        } catch (NumberFormatException e) {
            log.warn("\"approval.defaultmaxextensiontime\" is not a decimal number. Using default value: " + value);
        }
        return value * 1000L;
    }
    
    /**
     * Excluded classes from approval.
     */
    public static String getApprovalExcludedClasses() {
        return EjbcaConfigurationHolder.getExpandedString("approval.excludedClasses");
    }

    /**
     * Parameter specifying amount of free memory (Mb) before alarming
     */
    public static long getHealthCheckAmountFreeMem() {
        long value = 1;
        try {
            value = Long.parseLong(EjbcaConfigurationHolder.getString("healthcheck.amountfreemem"));
        } catch (NumberFormatException e) {
            log.warn("\"healthcheck.amountfreemem\" or \"ocsphealthcheck.amountfreemem\" is not a decimal number. Using default value: " + value);
        }
        return value * 1024L * 1024L;
    }

    /**
     * Parameter specifying database test query string. Used to check that the database is operational.
     */
    public static String getHealthCheckDbQuery() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.dbquery");
    }

    /**
     * Parameter to specify location of file containing information about maintenance
     */
    public static String getHealthCheckAuthorizedIps() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.authorizedips");
    }

    /**
     * Parameter to specify if the check of CA tokens should actually perform a signature test on the CA token.
     */
    public static boolean getHealthCheckCaTokenSignTest() {
        return TRUE.equalsIgnoreCase(EjbcaConfigurationHolder.getString("healthcheck.catokensigntest"));
    }

    /**
     * Parameter to specify if a connection test of publishers should be performed.
     */
    public static boolean getHealthCheckPublisherConnections() {
        return TRUE.equalsIgnoreCase(EjbcaConfigurationHolder.getString("healthcheck.publisherconnections"));
    }

    /**
     * Parameter to specify location of file containing information about maintenance
     */
    public static String getHealthCheckMaintenanceFile() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.maintenancefile");
    }

    /**
     * Parameter to configure name of maintenance property.
     */
    public static String getHealthCheckMaintenancePropertyName() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.maintenancepropertyname");
    }

    /**
     * @return Text string used to say that every thing is ok with this node.
     */
    public static String getOkMessage() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.okmessage");
    }
    
    /**
     * 
     * @return true if an error code 500 should be sent in case of error.
     */
    public static boolean getSendServerError() {
     return TRUE.equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString("healthcheck.sendservererror"));
    }
    
    /**
     * 
     * @return a static error message instead of one generated by the HealthChecker
     */
    public static String getCustomErrorMessage() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.customerrormessage");
    }

    /**
     * Class performing the healthcheck. Must implement the IHealthCheck interface.
     */
    public static String getHealthCheckClassPath() {
        return EjbcaConfigurationHolder.getExpandedString("healthcheck.classpath");
    }

    /**
     * Parameter to specify if retrieving endEntity profiles in EndEntityProfileSessionBean should be cached, and in that case for how long.
     */
    public static long getCacheEndEntityProfileTime() {
        long time = 1000; // cache 1 second is the default
        try {
            time = Long.valueOf(EjbcaConfigurationHolder.getString("eeprofiles.cachetime"));
        } catch (NumberFormatException e) {
            log.error("Invalid value in eeprofiles.cachetime, must be decimal number (milliseconds to cache EndEntity profiles): " + e.getMessage());
        }
        return time;
    }
    
    /**
     * Parameter to specify if retrieving approval profiles in ApprovalProfileSessionBean should be cached, and in that case for how long.
     */
    public static long getCacheApprovalProfileTime() {
        long time = 1000; // cache 1 second is the default
        try {
            time = Long.valueOf(EjbcaConfigurationHolder.getString("approvalprofiles.cachetime"));
        } catch (NumberFormatException e) {
            log.error("Invalid value in approvalprofiles.cachetime, must be decimal number (milliseconds to cache approval profiles): " + e.getMessage());
        }
        return time;
    }
    
    /**
     * Parameter to specify if retrieving Publishers from PublisherSession should be cached, and in that case for how long.
     */
    public static long getCachePublisherTime() {
        final String value = EjbcaConfigurationHolder.getString("publisher.cachetime");
        long time = 1000; // cache 1 second is the default
        try {
            if (value!=null) {
                time = Long.valueOf(value);
            }
        } catch (NumberFormatException e) {
            log.error("Invalid value in publisher.cachetime, must be decimal number (milliseconds to cache Publisher): " + e.getMessage());
        }
        return time;
    }

    /** Custom Available Access Rules. */
    public static String[] getCustomAvailableAccessRules() {
    	return StringUtils.split(EjbcaConfigurationHolder.getString("ejbca.customavailableaccessrules"), ';');
    }

    /**
     * Parameter to specify if how many rounds the BCrypt algorithm should process passwords stored in the database.
     * 0 means use the old way instead of BCrypt.
     */
    public static int getPasswordLogRounds() {
    	final String PROPERTY_NAME = "ejbca.passwordlogrounds";
        int time = 1; // only 1 single round is the default
        try {
            time = Integer.valueOf(EjbcaConfigurationHolder.getString(PROPERTY_NAME));
        } catch (NumberFormatException e) {
            log.error("Invalid value in " + PROPERTY_NAME + ", must be decimal number, using 1 round: " + e.getMessage());
        }
        return time;
    }
    
    public static String getCliDefaultUser() {
        return EjbcaConfigurationHolder.getString("ejbca.cli.defaultusername");
    }
    
    public static String getCliDefaultPassword() {
        return EjbcaConfigurationHolder.getString("ejbca.cli.defaultpassword");
    }

    public static String getScepDefaultCA() {
        return EjbcaConfigurationHolder.getString("scep.defaultca");
    }

    /** @return true if publishers should be invoked in parallel instead of sequentially. */
    @Deprecated // EJBCA 6.3.0 safety for the new Parallel publishing feature. Remove when default is considered stable.
    public static boolean isPublishParallelEnabled() {
        return getBooleanProperty("publish.parallel.enabled", true);
    }

    /** @return true if TCP keep alive should be used for outgoing peer connections. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static boolean isPeerSoKeepAlive() {
        return getBooleanProperty("peerconnector.connection.sokeepalive", true);
    }

    /** @return true if Nagle's algorithm should be disabled for outgoing peer connections. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static boolean isPeerTcpNoDelay() {
        return getBooleanProperty("peerconnector.connection.tcpnodelay", false);
    }

    /** @return the socket timeout in milliseconds for outgoing peer connections. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static int getPeerSoTimeoutMillis() {
        return getIntProperty("peerconnector.connection.sotimeout", 20000);
    }

    /** @return the maximum pool size for outgoing peer connections. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static int getPeerMaxPoolSize() {
        return getIntProperty("peerconnector.connection.maxpoolsize", 100);
    }

    /** @return the number of database entries to compare at the time when doing background synchronization of certificate data. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static int getPeerSyncBatchSize() {
        return getIntProperty("peerconnector.sync.batchsize", 2000);
    }

    /** @return the maximum number of updates to send in parallel when doing background synchronization of certificate data. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static int getPeerSyncConcurrency() {
        return getIntProperty("peerconnector.sync.concurrency", 12);
    }

    /** @return the largest allowed incoming peer message that will be processed. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static int getPeerIncomingMaxMessageSize() {
        return getIntProperty("peerconnector.incoming.maxmessagesize", 134217728);
    }

    /** @return how long a peer can be absent in milliseconds before (re-)authentication is triggered. */
    @Deprecated // EJBCA 6.3.0 safety for the new PeerConnector feature. Remove when default is considered stable.
    public static long getPeerIncomingAuthCacheTimeMillis() {
        return Integer.valueOf(getIntProperty("peerconnector.incoming.authcachetime", 60000)).longValue();
    }

    public static long getPeerDataCacheTime() {
        return getLongProperty("peerconnector.cachetime", 60000L);
    }

    /** @return the value as a boolean or the default otherwise. */
    private static boolean getBooleanProperty(final String key, final boolean defaultValue) {
        final String value = EjbcaConfigurationHolder.getString(key);
        if (defaultValue) {
            return !Boolean.FALSE.toString().equalsIgnoreCase(value);
        } else {
            return !Boolean.TRUE.toString().equalsIgnoreCase(value);
        }
    }
    
    /** @return the value as an int or the default otherwise. */
    private static int getIntProperty(final String key, final int defaultValue) {
        final String value = EjbcaConfigurationHolder.getString(key);
        int ret = defaultValue;
        try {
            if (value!=null) {
                ret = Integer.valueOf(value);
            }
        } catch (NumberFormatException e) {
            log.error("Invalid value configured for '"+key+"', must be decimal number: " + e.getMessage());
        }
        return ret;
    }

    /** @return the value as an long or the default otherwise. */
    private static long getLongProperty(final String key, final long defaultValue) {
        final String value = EjbcaConfigurationHolder.getString(key);
        long ret = defaultValue;
        try {
            if (value!=null) {
                ret = Long.valueOf(value);
            }
        } catch (NumberFormatException e) {
            log.error("Invalid value configured for '"+key+"', must be decimal number: " + e.getMessage());
        }
        return ret;
    }
   
}
