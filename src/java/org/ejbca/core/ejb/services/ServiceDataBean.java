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

package org.ejbca.core.ejb.services;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;

/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a service configuration used by the monitoring services framework
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  name (of the service)
 *  data (Data saved concerning the service)
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a service configuration"
 *   display-name="ServiceDataDataEB"
 *   name="ServiceData"
 *   jndi-name="ServiceData"
 *   local-jndi-name="ServiceDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="ServiceDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *   
 * @ejb.persistence table-name = "ServiceData"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.services.ServiceDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.services.ServiceDataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="org.ejbca.core.ejb.services.ServiceDataLocal findByName(java.lang.String name)"
 *   query="SELECT OBJECT(a) from ServiceDataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT OBJECT(a) from ServiceDataBean a"
 *
 * @ejb.transaction type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class ServiceDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(ServiceDataBean.class);

    private ServiceConfiguration serviceConfiguration = null;

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
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getData();

    /**
     * @ejb.persistence
     */
    public abstract void setData(String data);

    /**
     * Method that returns the service configuration data and updates it if nessesary.
     *
     * @ejb.interface-method view-type="local"
     */
    public ServiceConfiguration getServiceConfiguration() {

        if (serviceConfiguration == null) {
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

            serviceConfiguration = new ServiceConfiguration();
            serviceConfiguration.loadData(data);
        }

        return serviceConfiguration;
    }

    /**
     * Method that saves the service configuration data to database.
     *
     * @ejb.interface-method view-type="local"
     */
    public void setServiceConfiguration(ServiceConfiguration serviceConfiguration) {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)serviceConfiguration.saveData());
        
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

        this.serviceConfiguration = serviceConfiguration;        
    }


    //
    // Fields required by Container
    //
    /**
     * Passivates bean, resets CA data.
     */
    public void ejbPassivate() {
        this.serviceConfiguration = null;
    }


    /**
     * Entity Bean holding data of a service configuration.
     *
     * @return null
     * @ejb.create-method view-type="local"
     */
    public Integer ejbCreate(Integer id, String name, ServiceConfiguration serviceConfiguration) throws CreateException {
        setId(id);
        setName(name);

        if (serviceConfiguration != null)
            setServiceConfiguration(serviceConfiguration);

        log.debug("Created Service Configuration " + name);
        return id;
    }

    public void ejbPostCreate(Integer id, String name, ServiceConfiguration serviceConfiguration) {
        // Do nothing. Required.
    }
}
