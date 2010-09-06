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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;

/**
 * Representation of a service configuration used by the monitoring services framework.
 * 
 * @version $Id$
 */
@Entity
@Table(name="ServiceData")
public class ServiceData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ServiceData.class);

	private ServiceConfiguration serviceConfiguration = null;
	
	private Integer id;
	private String name;
	private String data;

    /**
     * Entity Bean holding data of a service configuration.
     */
    public ServiceData(Integer id, String name, ServiceConfiguration serviceConfiguration) {
        setId(id);
        setName(name);
        if (serviceConfiguration != null) {
        	setServiceConfiguration(serviceConfiguration);
        }
        log.debug("Created Service Configuration " + name);
    }
    
    public ServiceData() { }

    /** Primary key. */
	@Id
	@Column(name="id")
	public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }

    /** Name of the service. */
	@Column(name="name")
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    /** Data saved concerning the service. */
	// DB2: CLOB(100K) [100K (2GBw/o)], Derby: LONG VARCHAR [32,700 characters], Informix: TEXT (2147483648 b?), Ingres: CLOB [2GB], MSSQL: TEXT [2,147,483,647 bytes], MySQL: TEXT [65535 chars], Oracle: CLOB [4G chars], Sybase: TEXT [2,147,483,647 chars]  
	@Column(name="data", length=32700)
	@Lob
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    /**
     * Method that returns the service configuration data and updates it if necessary.
     */
    @Transient
    public ServiceConfiguration getServiceConfiguration() {
        if (serviceConfiguration == null) {
            java.beans.XMLDecoder decoder;
        	try {
        		decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
        	} catch (UnsupportedEncodingException e) {
        		throw new RuntimeException(e);
        	}
            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);
        	float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
            ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
            serviceConfiguration.loadData(data);
        	if ( ((serviceConfiguration != null) && (Float.compare(oldversion, serviceConfiguration.getVersion()) != 0))) {
        		setServiceConfiguration(serviceConfiguration);
        	} else {
                this.serviceConfiguration = serviceConfiguration;
        	}
        }
        return serviceConfiguration;
    }

    /**
     * Method that saves the service configuration data to database.
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
                log.debug("Service data: \n" + baos.toString("UTF8"));
            }
            setData(baos.toString("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        this.serviceConfiguration = serviceConfiguration;        
    }




  

 
}
