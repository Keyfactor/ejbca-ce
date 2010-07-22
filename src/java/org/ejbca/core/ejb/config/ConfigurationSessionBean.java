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
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;

/**
 * This bean handles configuration changes for system tests.
 * 
 * @version $Id$
 * 
 * @ejb.bean
 *   display-name="ConfigurationSessionBean"
 *   name="ConfigurationSession"
 *   jndi-name="ConfigurationSession"
 *   view-type="remote"
 *   type="Stateless"
 *   transaction-type="Container"
 *   generate="true"
 *
 * @ejb.transaction type="Supports"
 * 
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.config.IConfigurationSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.config.IConfigurationSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   remote-class="org.ejbca.core.ejb.upgrade.IConfigurationSessionRemote"
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ConfigurationSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ConfigurationSessionBean implements ConfigurationSessionRemote {

    private static final long serialVersionUID = 1L;

    public void ejbCreate() { }
	public void ejbRemove() { }

	/**
	 * Verify that EJBCA isn't running in production mode. 
	 */
	private void assertIsNotInProductionMode() throws EJBException {
		if (EjbcaConfiguration.getIsInProductionMode()) {
			throw new EJBException("Configuration can not be altered in production mode.");
		}
	}
	
	/**
	 * Try to backup the current configuration.
	 * @return false if a backup already exists.
	 * 
	 * @ejb.interface-method
	 */
	public boolean backupConfiguration() {
		assertIsNotInProductionMode();
		return ConfigurationHolder.backupConfiguration();
	}
	
	/**
	 * Restore configuration from backup.
	 * @return false if no backup exists.
	 * 
	 * @ejb.interface-method
	 */
	public boolean restoreConfiguration() {
		assertIsNotInProductionMode();
		return ConfigurationHolder.restoreConfiguration();
	}
	
	/**
	 * Makes sure there is a backup of the configuration and then alters the
	 * active configuration with all the properties.
	 * 
	 * @ejb.interface-method
	 */
	public boolean updateProperties(Properties properties) {
		assertIsNotInProductionMode();
		return ConfigurationHolder.updateConfiguration(properties);
	}
	
	/**
	 * Makes sure there is a backup of the configuration and then alters the
	 * active configuration with the property.
	 * 
	 * @ejb.interface-method
	 */
	public boolean updateProperty(String key, String value) {
		assertIsNotInProductionMode();
		return ConfigurationHolder.updateConfiguration(key, value);
	}

	/**
	 * Verifies that the property is set to the expected value.
	 * 
	 * @ejb.interface-method
	 */
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

	/**
	 * Returns a property from the current server configuration
	 * 
	 * @ejb.interface-method
	 */
	public String getProperty(String key, String defaultValue) {
		assertIsNotInProductionMode();
		return ConfigurationHolder.getString(key, defaultValue);
	}

	/**
	 * @return all currently used properties
	 * 
	 * @ejb.interface-method
	 */
	public Properties getAllProperties() {
		assertIsNotInProductionMode();
		return ConfigurationHolder.getAsProperties();
	}
}
