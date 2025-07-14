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

import org.cesecore.configuration.ConfigurationBase;

public class GlobalEndEntityProfileConfiguration extends ConfigurationBase {
    private static final long serialVersionUID = 1L;
    public static final String EEP_CONFIGURATION_ID = "GLOBAL_EEP_CONFIG";

    private static final   String ENABLEEEPROFILELIMITATIONS   = "endentityprofilelimitations";

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, LATEST_VERSION);
        }
    }

    @Override
    public String getConfigurationId() {
        return EEP_CONFIGURATION_ID;
    }

    public boolean getEnableEndEntityProfileLimitations() {
        return getBoolean(ENABLEEEPROFILELIMITATIONS, true);
    }

    public void setEnableEndEntityProfileLimitations(final boolean value) {
        putBoolean(ENABLEEEPROFILELIMITATIONS, value);
    }

}
