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

package org.ejbca.core.ejb.ra.userdatasource;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;

/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a user data source to the ra
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  name (of the user data source)
 *  updatecount, help counter incremented each update used to check if a user data source proxy class should update its data
 *  userdatasource (Data saved concerning the user data source)
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a user data source"
 *   display-name="UserDataSourceDataEB"
 *   name="UserDataSourceData"
 *   jndi-name="UserDataSourceData"
 *   local-jndi-name="UserDataSourceDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="UserDataSourceDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *   
 * @ejb.persistence table-name = "UserDataSourceData"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ra.userdatasource.UserDataSourceDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ra.userdatasource.UserDataSourceDataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="org.ejbca.core.ejb.ra.userdatasource.UserDataSourceDataLocal findByName(java.lang.String name)"
 *   query="SELECT OBJECT(a) from UserDataSourceDataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT OBJECT(a) from UserDataSourceDataBean a"
 *
 * @ejb.transaction type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class UserDataSourceDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(UserDataSourceDataBean.class);

    private BaseUserDataSource userdatasource = null;

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

    /**
     * @ejb.persistence
     */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getName();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setName(String name);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract int getUpdateCounter();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUpdateCounter(int updatecounter);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getData();

    /**
     * @ejb.persistence
     */
    public abstract void setData(String data);

    /**
     * Method that returns the userdatasource data and updates it if nessesary.
     *
     * @ejb.interface-method view-type="local"
     */
    public BaseUserDataSource getUserDataSource() {

        if (userdatasource == null) {
            java.beans.XMLDecoder decoder;
            try {
                decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException e) {
                throw new EJBException(e);
            }
            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);

            switch (((Integer) (data.get(BaseUserDataSource.TYPE))).intValue()) {
                case CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER:
                	userdatasource = new CustomUserDataSourceContainer();
                    break;
            }

            userdatasource.loadData(data);
        }

        return userdatasource;
    }

    /**
     * Method that saves the userdatasource data to database.
     *
     * @ejb.interface-method view-type="local"
     */
    public void setUserDataSource(BaseUserDataSource userdatasource) {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)userdatasource.saveData());
        
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();

        try {
            if (log.isDebugEnabled()) {
                log.debug("Profiledata: \n" + baos.toString("UTF8"));
            }
            setData(baos.toString("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);
        }

        this.userdatasource = userdatasource;
        setUpdateCounter(getUpdateCounter() + 1);
    }


    //
    // Fields required by Container
    //
    /**
     * Passivates bean, resets CA data.
     */
    public void ejbPassivate() {
        this.userdatasource = null;
    }


    /**
     * Entity Bean holding data of a userdatasource.
     *
     * @return null
     * @ejb.create-method view-type="local"
     */
    public Integer ejbCreate(Integer id, String name, BaseUserDataSource userdatasource) throws CreateException {
        setId(id);
        setName(name);
        this.setUpdateCounter(0);
        if (userdatasource != null)
            setUserDataSource(userdatasource);

        log.debug("Created User Data Source " + name);
        return id;
    }

    public void ejbPostCreate(Integer id, String name, BaseUserDataSource userdatasource) {
        // Do nothing. Required.
    }
}
