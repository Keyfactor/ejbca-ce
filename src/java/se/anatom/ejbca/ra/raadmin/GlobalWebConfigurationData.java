

package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**

 * For docs, see GlobalWebConfigurationDataBean

 **/

public interface GlobalWebConfigurationData extends javax.ejb.EJBObject {



    // public methods

    public Integer getConfigurationId() throws RemoteException;

    public void setConfigurationId(Integer id) throws RemoteException;

    public GlobalConfiguration getGlobalConfiguration() throws RemoteException;

    public void setGlobalConfiguration(GlobalConfiguration globalconfiguration) throws RemoteException;
    
}

