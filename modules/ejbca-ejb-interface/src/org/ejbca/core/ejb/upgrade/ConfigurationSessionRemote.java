package org.ejbca.core.ejb.upgrade;

import java.rmi.RemoteException;
import java.util.Properties;

import javax.ejb.Remote;

@Remote
public interface ConfigurationSessionRemote {
    /**
     * Try to backup the current configuration.
     * 
     * @return false if a backup already exists.
     */
    public boolean backupConfiguration() throws RemoteException;

    /**
     * Restore configuration from backup.
     * 
     * @return false if no backup exists.
     */
    public boolean restoreConfiguration() throws RemoteException;

    /**
     * Makes sure there is a backup of the configuration and then alters the
     * active configuration with all the properties.
     */
    public boolean updateProperties(Properties properties) throws RemoteException;

    /**
     * Makes sure there is a backup of the configuration and then alters the
     * active configuration with the property.
     */
    public boolean updateProperty(String key, String value) throws RemoteException;

    /**
     * Verifies that the property is set to the expected value.
     */
    public boolean verifyProperty(String key, String value) throws RemoteException;

    /**
     * Returns a property from the current server configuration
     */
    public String getProperty(String key, String defaultValue) throws RemoteException;

    public Properties getAllProperties() throws RemoteException;
}
