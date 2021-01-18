package org.ejbca.config;

import org.cesecore.configuration.ConfigurationBase;

/**
 * Configuration for the Microsoft Auto Enrollment
 */
public class MSAutoEnrollmentConfiguration extends ConfigurationBase {
    private static final long serialVersionUID = 1L;
    public static final String CONFIGURATION_ID = "MS_AUTO_ENROLLMENT";

    // Configuration elements here.

    // MSAE Settings
    private static final String IS_USE_SSL = "isUseSSL";


    public MSAutoEnrollmentConfiguration() {
        initWithDefaults();
    }

    private void initWithDefaults() {
        // TODO: Set default values.
        data.put(IS_USE_SSL, false);
    }

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, Float.valueOf(LATEST_VERSION));
        }
    }

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    public boolean isUseSSL() {
        return Boolean.TRUE.equals(data.get(IS_USE_SSL));
    }

    public void setIsUseSsl(final boolean isUseSsl) {
        data.put(IS_USE_SSL, Boolean.valueOf(isUseSsl));
    }
}
