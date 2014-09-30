/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.ScepConfiguration;

/**
 * Entity Bean representing admin web interface global configuration.
 * 
 * @version $Id$
 */
@Entity
@Table(name="GlobalConfigurationData")
public class GlobalConfigurationData extends ProtectedData implements Serializable {

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
	public GlobalConfigurationData(String configurationId, Configuration configuration) {
		setConfigurationId(configurationId);
		setConfiguration(configuration);
		log.debug("Created configuration "+configurationId);
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
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@SuppressWarnings("rawtypes")
    @Transient
	private HashMap getData() {
		return JBossUnmarshaller.extractLinkedHashMap(getDataUnsafe());
	}
	
	@SuppressWarnings("rawtypes")
    private void setData(HashMap data) { setDataUnsafe(JBossUnmarshaller.serializeObject(data)); }

	/** 
	 * Method that returns the global configuration and updates it if necessary.
	 */
	@Transient
	public Configuration getConfiguration(String configID){
	    Configuration returnval = null;
	    if(StringUtils.equals(configID, Configuration.GlobalConfigID) ) {
	        returnval = new GlobalConfiguration();
	    } else if(StringUtils.equals(configID, Configuration.CMPConfigID)) {
	        returnval = new CmpConfiguration();
	    } else if(StringUtils.equals(configID, Configuration.ScepConfigID)) {
	        returnval = new ScepConfiguration();
	    }
		returnval.loadData(getData());
		return returnval;
	}

	/** 
	 * Method that saves the global configuration to database.
	 */
	@SuppressWarnings("rawtypes")
    public void setConfiguration(Configuration configuration){
		setData((HashMap) configuration.saveData());   
	}

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getConfigurationId()).append(getData());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getConfigurationId();
    }

    //
    // End Database integrity protection methods
    //

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static GlobalConfigurationData findByConfigurationId(EntityManager entityManager, String configurationId) {
		return entityManager.find(GlobalConfigurationData.class, configurationId);
	}
}
