package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import java.util.HashMap;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing ra admin web interface global configuration.
 * Information stored:
 * <pre>
 * ConfigurationId (Should always be 0)
 * GlobalConfiguration
 * </pre>
 *
 * @version $Id: GlobalConfigurationDataBean.java,v 1.1 2003-09-04 09:28:54 herrvendil Exp $
 */
public abstract class GlobalConfigurationDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(GlobalConfigurationDataBean.class);

    public abstract String getConfigurationId();
    public abstract void setConfigurationId(String id);
    public abstract HashMap getData();
    public abstract void setData(HashMap data);
    
    
    /** 
     * Method that returns the globalconfigurtation and updates it if nessesary.
     */
    public GlobalConfiguration getGlobalConfiguration(){
      GlobalConfiguration returnval = new GlobalConfiguration();
      returnval.loadData((Object) getData());
      return returnval;
    }
    
    /** 
     * Method that saves the global configuration to database.
     */
    public void setGlobalConfiguration(GlobalConfiguration globalconfiguration){
      setData((HashMap) globalconfiguration.saveData());   
    }
    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of raadmin configuration.
     * Create by sending in the id and string representation of globalconfiguration
     * @param id the unique id of globalconfiguration.
     * @param globalconfiguration is the serialized string representation of the global configuration.
     * @return GlobalConfigurationDataPK primary key
     *
     **/


    public String ejbCreate(String configurationId, GlobalConfiguration globalConfiguration) throws CreateException {

        setConfigurationId(configurationId);
        setGlobalConfiguration(globalConfiguration);

        log.debug("Created global configuration "+configurationId);
        return configurationId;
    }

    public void ejbPostCreate(String id, GlobalConfiguration globalconfiguration) {
        // Do nothing. Required.
    }
}
