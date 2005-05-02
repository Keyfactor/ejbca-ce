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
 * @version $Id: GlobalConfigurationDataBean.java,v 1.6 2005-05-02 16:18:23 anatom Exp $
 *
 * @ejb.bean description="This enterprise bean entity represents global configuration of ra administration"
 * display-name="GlobalConfigurationDataEB"
 * name="GlobalConfigurationData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="GlobalConfigurationDataBean"
 * primkey-field="configurationId"
 *
 * @ejb.pk class="java.lang.String"
 * generate="false"
 *
 * @ejb.home
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ra.raadmin.GlobalConfigurationDataLocalHome"
 *
 * @ejb.interface
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="se.anatom.ejbca.ra.raadmin.GlobalConfigurationDataLocal"
 *
 * TODO How is this different from findByPrimaryKey ?
 * @ejb.finder
 *   description="findByConfigurationId"
 *   signature="se.anatom.ejbca.ra.raadmin.GlobalConfigurationDataLocal findByConfigurationId(java.lang.String id)"
 *   query="SELECT DISTINCT OBJECT(a) from GlobalConfigurationDataBean a WHERE a.configurationId=?1"
 *
 */
public abstract class GlobalConfigurationDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(GlobalConfigurationDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getConfigurationId();

    /**
     * @ejb.interface-method
     */
    public abstract void setConfigurationId(String id);

    /**
     * @ejb.persistence
     */
    public abstract HashMap getData();

    /**
     */
    public abstract void setData(HashMap data);

    /** 
     * Method that returns the globalconfigurtation and updates it if nessesary.
     * @ejb.interface-method
     */
    public GlobalConfiguration getGlobalConfiguration(){
      GlobalConfiguration returnval = new GlobalConfiguration();
      returnval.loadData(getData());
      return returnval;
    }
    
    /** 
     * Method that saves the global configuration to database.
     * @ejb.interface-method
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
     * @ejb.create-method
     */
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
