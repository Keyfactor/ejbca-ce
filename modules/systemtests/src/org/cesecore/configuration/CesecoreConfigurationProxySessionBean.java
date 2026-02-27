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
package org.cesecore.configuration;

import org.cesecore.config.ConfigurationHolder;

import com.keyfactor.util.string.StringConfigurationCache;

import jakarta.ejb.Stateless;

/**
 * 
 */
@Stateless
public class CesecoreConfigurationProxySessionBean implements CesecoreConfigurationProxySessionRemote {

    @Override
    public void setConfigurationValue(String key, String value) {
        ConfigurationHolder.updateConfiguration(key, value);      
    }

    @Override
    public String getConfigurationValue(String key) {
        return ConfigurationHolder.getExpandedString(key);
    }

    @Deprecated(since = "9.5.0")
    @Override
    public char[] getForbiddenCharacters() {
        return StringConfigurationCache.INSTANCE.getForbiddenCharacters();
    }
}
