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

import java.io.Serializable;

import org.cesecore.configuration.ConfigurationBase;

/**
 *
 */
public class GlobalCaConfiguration extends ConfigurationBase implements Serializable {

    public static final String CA_CONFIGURATION_ID = "GLOBAL_CA";
    
    private static final long serialVersionUID = 1L;
    
    private static final String ENABLE_ICAO_CA_NAME_CHANGE = "enableIcaoCaNameChange";
    
    public GlobalCaConfiguration() {
        super();
        //Default values
        setEnableIcaoCANameChange(false);
    }
    
    @Override
    public void upgrade() {

    }

    public boolean getEnableIcaoCANameChange() {
        return getBoolean(ENABLE_ICAO_CA_NAME_CHANGE, false);
    }
    
    public void setEnableIcaoCANameChange(final boolean value) {
        putBoolean(ENABLE_ICAO_CA_NAME_CHANGE, value);
    }
    
    @Override
    public String getConfigurationId() {
        return CA_CONFIGURATION_ID;
    }

}
