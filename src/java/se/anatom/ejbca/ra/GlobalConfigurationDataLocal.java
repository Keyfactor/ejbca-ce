package se.anatom.ejbca.ra;

import se.anatom.ejbca.ra.GlobalConfiguration;


/**
 * For docs, see GlobalWebConfigurationDataBean
 */
public interface GlobalConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getConfigurationId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public void setConfigurationId(String id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public GlobalConfiguration getGlobalConfiguration();

    /**
     * DOCUMENT ME!
     *
     * @param globalConfiguration DOCUMENT ME!
     */
    public void setGlobalConfiguration(GlobalConfiguration globalConfiguration);
}
