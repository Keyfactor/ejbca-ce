package se.anatom.ejbca.ra;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.util.HashMap;
import org.apache.log4j.*;

import se.anatom.ejbca.ra.GlobalConfiguration;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing ra admin web interface global configuration.
 * Information stored:
 * <pre>
 * ConfigurationId (Should always be 0)
 * GlobalConfiguration
 * </pre>
 *
 **/

public abstract class GlobalConfigurationDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance( GlobalConfigurationDataBean.class.getName() );
    protected EntityContext  ctx;

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

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

