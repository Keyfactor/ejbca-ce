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

import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.config.ConfigurationHolder;

import com.keyfactor.util.StringTools;
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
        OcspConfigurationCache.INSTANCE.reloadConfiguration();
    }

    @Override
    public String getConfigurationValue(String key) {
        return ConfigurationHolder.getExpandedString(key);
    }

    @Override
    public void setForbiddenCharacters(char[] forbiddenCharacters) {
        StringConfigurationCache.INSTANCE.setForbiddenCharacters(forbiddenCharacters);
        StringTools.CharSet.reset(); // reset reading of forbidden characters of we changed that
        
    }

    @Override
    public char[] getForbiddenCharacters() {
        return StringConfigurationCache.INSTANCE.getForbiddenCharacters();
    }
}
