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

import java.io.Serializable;
import java.util.HashMap;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.config.GlobalConfiguration;

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
	private int rowVersion = 0;
	private String rowProtection;

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
	
	//@Id @Column
	public String getConfigurationId() { return configurationId; }
	public void setConfigurationId(String configurationId) { this.configurationId = configurationId; }

	//@Column @Lob
	public Serializable getDataUnsafe() { return data; }
	/** DO NOT USE! Stick with setData(HashMap data) instead. */
	public void setDataUnsafe(Serializable data) { this.data = data; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	private HashMap getData() {
		return JBossUnmarshaller.extractLinkedHashMap(getDataUnsafe());
	}
	
	private void setData(HashMap data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }

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

	/** @return the found entity instance or null if the entity does not exist */
	public static GlobalConfigurationData findByConfigurationId(EntityManager entityManager, String configurationId) {
		return entityManager.find(GlobalConfigurationData.class, configurationId);
	}
}
