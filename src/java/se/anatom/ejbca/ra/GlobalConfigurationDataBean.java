package se.anatom.ejbca.ra;

import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing ra
 * admin web interface global configuration. Information stored:
 * <pre>
 * ConfigurationId (Should always be 0)
 * GlobalConfiguration
 * </pre>
 *
 * @version $Id: GlobalConfigurationDataBean.java,v 1.8 2003-07-24 08:43:31 anatom Exp $
 */
public abstract class GlobalConfigurationDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(GlobalConfigurationDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getConfigurationId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setConfigurationId(String id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract HashMap getData();

    /**
     * DOCUMENT ME!
     *
     * @param data DOCUMENT ME!
     */
    public abstract void setData(HashMap data);

    /**
     * Method that returns the globalconfigurtation and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public GlobalConfiguration getGlobalConfiguration() {
        GlobalConfiguration returnval = new GlobalConfiguration();
        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the global configuration to database.
     *
     * @param globalconfiguration DOCUMENT ME!
     */
    public void setGlobalConfiguration(GlobalConfiguration globalconfiguration) {
        setData((HashMap) globalconfiguration.saveData());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of raadmin configuration. Create by sending in the id and string
     * representation of globalconfiguration
     *
     * @param configurationId the unique id of globalconfiguration.
     * @param configurationId is the serialized string representation of the global configuration.
     *
     * @return GlobalConfigurationDataPK primary key
     */
    public String ejbCreate(String configurationId, GlobalConfiguration globalConfiguration)
        throws CreateException {
        setConfigurationId(configurationId);
        setGlobalConfiguration(globalConfiguration);

        log.debug("Created global configuration " + configurationId);

        return configurationId;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param globalconfiguration DOCUMENT ME!
     */
    public void ejbPostCreate(String id, GlobalConfiguration globalconfiguration) {
        // Do nothing. Required.
    }
}
