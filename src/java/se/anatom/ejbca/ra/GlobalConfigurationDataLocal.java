package se.anatom.ejbca.ra;


import java.rmi.RemoteException;
import java.math.BigInteger;

import se.anatom.ejbca.ra.GlobalConfiguration;

/**

 * For docs, see GlobalWebConfigurationDataBean

 **/

public interface GlobalConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public String getConfigurationId();
    public void setConfigurationId(String id);


    public GlobalConfiguration getGlobalConfiguration();
    public void setGlobalConfiguration(GlobalConfiguration globalConfiguration);
}

