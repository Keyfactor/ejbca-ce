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
 
package org.ejbca.core.ejb.ra.raadmin;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JBossUnmarshaller;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * Entity Bean representing admin web interface global configuration.
 * 
 * @version $Id$
 */
@Entity
@Table(name="GlobalConfigurationData")
public class GlobalConfigurationData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(GlobalConfigurationData.class);

	private String configurationId;
	private Serializable data;
	
	/**
	 * Entity holding data of admin's configuration.
	 * Create by sending in the id and string representation of global configuration
	 * @param id the unique id of global configuration.
	 * @param globalconfiguration is the serialized string representation of the global configuration.
	 */
	public GlobalConfigurationData(String configurationId, GlobalConfiguration globalConfiguration) {
		setConfigurationId(configurationId);
		setGlobalConfiguration(globalConfiguration);
		log.debug("Created global configuration "+configurationId);
	}
	
	public GlobalConfigurationData() { }

	@Id
	@Column(name="configurationId")
	public String getConfigurationId() { return configurationId; }
	public void setConfigurationId(String configurationId) { this.configurationId = configurationId; }

	@Column(name="data",length=17*1024*1024)
	@Lob
	private Serializable getDataUnsafe() {
		HashMap h = JBossUnmarshaller.extractObject(HashMap.class, data);	// This is a workaround for JBoss J2EE CMP Serialization
		if (h != null) {
			setDataUnsafe(h);
		}
		return data;
	}
	/** DO NOT USE! Stick with setData(HashMap data) instead. */
	private void setDataUnsafe(Serializable data) { this.data = data; }

	@Transient
	private HashMap getData() { return (HashMap) getDataUnsafe(); }
	private void setData(HashMap data) { setDataUnsafe(data); }

	/** 
	 * Method that returns the global configuration and updates it if necessary.
	 */
	@Transient
	public GlobalConfiguration getGlobalConfiguration(){
		GlobalConfiguration returnval = new GlobalConfiguration();
		returnval.loadData(getData());
		return returnval;
	}

	/** 
	 * Method that saves the global configuration to database.
	 */
	public void setGlobalConfiguration(GlobalConfiguration globalconfiguration){
		setData((HashMap) globalconfiguration.saveData());   
	}

	//
	// Search functions. 
	//

	public static GlobalConfigurationData findByConfigurationId(EntityManager entityManager, String configurationId) {
		return entityManager.find(GlobalConfigurationData.class,  configurationId);
	}
}
