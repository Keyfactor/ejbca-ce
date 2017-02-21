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
package org.ejbca.core.ejb.config;

import java.util.Properties;

import org.cesecore.configuration.ConfigurationBase;

/**
 * Object for keeping track of database content version.
 * 
 * @version $Id$
 */
public class GlobalUpgradeConfiguration extends ConfigurationBase {

    public static final String CONFIGURATION_ID = "UPGRADE";
   
    private static final long serialVersionUID = 1L;

    private static final String UPGRADED_TO_VERSION = "upgradedToVersion";
    private static final String POST_UPGRADED_TO_VERSION = "postUpgradedToVersion";
    private static final String EEP_IN_CERTIFICATE_DATA = "endEntityProfileInCertificateData";
    private static final String POST_UPGRADE_STARTED = "postUpgradeStarted";
    
    public String getUpgradedToVersion() {
        return (String) data.get(UPGRADED_TO_VERSION);
    }
    public void setUpgradedToVersion(final String version) {
        data.put(UPGRADED_TO_VERSION, version);
    }

    public String getPostUpgradedToVersion() {
        return (String) data.get(POST_UPGRADED_TO_VERSION);
    }
    public void setPostUpgradedToVersion(final String version) {
        data.put(POST_UPGRADED_TO_VERSION, version);
    }
    /** @return true if the endEntityProfileId column in CertificateData has been populated or false if not or value has not been set. */
    public boolean isEndEntityProfileInCertificateData() {
        return Boolean.parseBoolean((String) data.get(EEP_IN_CERTIFICATE_DATA));
    }
    public void setEndEntityProfileInCertificateData(final boolean value) {
        data.put(EEP_IN_CERTIFICATE_DATA, Boolean.valueOf(value).toString());
    }

    @Override
    public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    public Properties getAsProperties() {
        final Properties properties = new Properties();
        properties.put(UPGRADED_TO_VERSION, getUpgradedToVersion());
        properties.put(POST_UPGRADED_TO_VERSION, getPostUpgradedToVersion());
        return properties;
    }

    public long getPostUpgradeStarted() {
        final String value = (String) data.get(POST_UPGRADE_STARTED);
        if (value==null) {
            return 0L;
        }
        return Long.parseLong(value);
    }
    public void setPostUpgradeStarted(long startTimeMs) {
        data.put(POST_UPGRADE_STARTED, String.valueOf(startTimeMs));
    }
}
