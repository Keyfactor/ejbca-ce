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

import javax.ejb.Stateless;

import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.StringTools;

/**
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CesecoreConfigurationProxySessionRemote")
public class CesecoreConfigurationProxySessionBean implements CesecoreConfigurationProxySessionRemote {

    @Override
    public void setConfigurationValue(String key, String value) {
        ConfigurationHolder.updateConfiguration(key, value);
        StringTools.CharSet.reset(); // reset reading of forbidden characters of we changed that
        OcspConfigurationCache.INSTANCE.reloadConfiguration();
    }

    @Override
    public String getConfigurationValue(String key) {
        return ConfigurationHolder.getExpandedString(key);
    }

}
