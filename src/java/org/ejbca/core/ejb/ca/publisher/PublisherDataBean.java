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

package org.ejbca.core.ejb.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.util.Base64PutHashMap;

/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a publisher in the ca.
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  name (of the publisher)
 *  updatecount, help counter incremented each update used to check if a publisher proxy class should update its data
 *  publisher (Data saved concerning the publisher)
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a publisher"
 *   display-name="PublisherDataEB"
 *   name="PublisherData"
 *   jndi-name="PublisherData"
 *   local-jndi-name="PublisherDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="PublisherDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *   
 * @ejb.persistence table-name = "PublisherData"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.publisher.PublisherDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.publisher.PublisherDataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="org.ejbca.core.ejb.ca.publisher.PublisherDataLocal findByName(java.lang.String name)"
 *   query="SELECT OBJECT(a) from PublisherDataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT OBJECT(a) from PublisherDataBean a"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class PublisherDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(PublisherDataBean.class);

    private BasePublisher publisher = null;

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="id"
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

    /**
     */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence column-name="name"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getName();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setName(String name);

    /**
     * @ejb.persistence column-name="updateCounter"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getUpdateCounter();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUpdateCounter(int updatecounter);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="data"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getData();

    /**
     */
    public abstract void setData(String data);

    /**
     * Method that gets the cached publisher, if any.
     *
     * @ejb.interface-method view-type="local"
     */
    public BasePublisher getCachedPublisher() {
    	return publisher;
    }
    

    /**
     * Method that saves the publisher data to database.
     *
     * @ejb.interface-method view-type="local"
     */
    public void setPublisher(BasePublisher publisher) {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)publisher.saveData());
        
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

        this.publisher = publisher;
        setUpdateCounter(getUpdateCounter() + 1);
    }


    //
    // Fields required by Container
    //
    /**
     * Passivates bean, resets CA data.
     */
    public void ejbPassivate() {
        this.publisher = null;
    }


    /**
     * Entity Bean holding data of a publisher.
     *
     * @return null
     * @ejb.create-method view-type="local"
     */
    public Integer ejbCreate(Integer id, String name, BasePublisher publisher) throws CreateException {
        setId(id);
        setName(name);
        this.setUpdateCounter(0);
        if (publisher != null) {
            setPublisher(publisher);
        }

        log.debug("Created Publisher " + name);
        return id;
    }

    public void ejbPostCreate(Integer id, String name, BasePublisher publisher) {
        // Do nothing. Required.
    }
}
