package se.anatom.ejbca.ra.raadmin;


import java.rmi.RemoteException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**

 * For docs, see GlobalWebConfigurationDataBean

 **/

public interface GlobalWebConfigurationDataLocal extends javax.ejb.EJBLocalObject {



    // public methods

    public Integer getConfigurationId();

    public void setConfigurationId(Integer id);

    public GlobalConfiguration getGlobalConfiguration();

    public void setGlobalConfiguration(GlobalConfiguration globalconfiguration);

}

