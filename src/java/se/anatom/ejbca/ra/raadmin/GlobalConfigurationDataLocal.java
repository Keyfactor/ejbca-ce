package se.anatom.ejbca.ra.raadmin;


import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;

/**
For docs, see GlobalWebConfigurationDataBean
*/
public interface GlobalConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getConfigurationId();
    public void setConfigurationId(String id);
    public GlobalConfiguration getGlobalConfiguration();
    public void setGlobalConfiguration(GlobalConfiguration globalConfiguration);
}

