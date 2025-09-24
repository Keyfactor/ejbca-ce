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
    private static final String CA_CERTIFICATE_CACHE_TIME = "caCertificateCacheTimeMillis";
    
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
    
    public long getCaCertificateCacheTimeMillis() {
        if(data.get(CA_CERTIFICATE_CACHE_TIME) == null) {
            //set the default
            try {
                setCaCertificateCacheTimeMillis(300*1000);
            } catch (InvalidConfigurationException e) {    
                throw new IllegalStateException("Default value of 300000 was somehow negative.", e);
            }  
        }
        return (long) data.get(CA_CERTIFICATE_CACHE_TIME);
    }
    
    public void setCaCertificateCacheTimeMillis(final long caCertificateCacheTimeMillis) throws InvalidConfigurationException {
        if(caCertificateCacheTimeMillis < 0) {
            throw new InvalidConfigurationException("Validity time must be a greater than or equal to 0, was " + caCertificateCacheTimeMillis);
        }
        data.put(CA_CERTIFICATE_CACHE_TIME, caCertificateCacheTimeMillis);
    }
    
    public void setCaCertificateCacheTimeSeconds(final long caCertificateCacheTimeSeconds) throws InvalidConfigurationException {
        setCaCertificateCacheTimeMillis(caCertificateCacheTimeSeconds * 1000);
    }
    
    public long getCaCertificateCacheTimeSeconds() {
        return getCaCertificateCacheTimeMillis()/1000;
    }
    
    @Override
    public String getConfigurationId() {
        return CA_CONFIGURATION_ID;
    }

}
