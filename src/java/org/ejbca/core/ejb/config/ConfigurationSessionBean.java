/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.ejbca.config.ConfigurationHolder;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;

/**
 * This bean handles configuration changes for system tests.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ConfigurationSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ConfigurationSessionBean implements ConfigurationSessionRemote {

    private static final long serialVersionUID = 1L;

    /** Verify that EJBCA isn't running in production mode. */
    private void assertIsNotInProductionMode() throws EJBException {
        if (EjbcaConfiguration.getIsInProductionMode()) {
            throw new EJBException("Configuration can not be altered in production mode.");
        }
    }

    @Override
    public boolean backupConfiguration() {
        assertIsNotInProductionMode();
        return ConfigurationHolder.backupConfiguration();
    }

    @Override
    public boolean restoreConfiguration() {
        assertIsNotInProductionMode();
        return ConfigurationHolder.restoreConfiguration();
    }

    @Override
    public boolean updateProperties(Properties properties) {
        assertIsNotInProductionMode();
        return ConfigurationHolder.updateConfiguration(properties);
    }

    @Override
    public boolean updateProperty(String key, String value) {
        assertIsNotInProductionMode();
        return ConfigurationHolder.updateConfiguration(key, value);
    }

    @Override
    public boolean verifyProperty(String key, String value) {
        assertIsNotInProductionMode();
        String configValue = ConfigurationHolder.getString(key, null);
        if ((value == null && configValue != null) || (value != null && configValue == null)) {
            return false;
        }
        if (value == null && configValue == null) {
            return true;
        }
        return value.equals(configValue);
    }

    @Override
    public String getProperty(String key, String defaultValue) {
        assertIsNotInProductionMode();
        return ConfigurationHolder.getString(key, defaultValue);
    }

    @Override
    public Properties getAllProperties() {
        assertIsNotInProductionMode();
        return ConfigurationHolder.getAsProperties();
    }
}
