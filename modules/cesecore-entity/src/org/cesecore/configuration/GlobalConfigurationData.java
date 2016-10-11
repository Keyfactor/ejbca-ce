/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.cesecore.configuration;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.CertTools;
import org.cesecore.util.JBossUnmarshaller;

/**
 * Entity Bean for database persisted configurations
 * 
 * @version $Id$
 */
@Entity
@Table(name="GlobalConfigurationData")
public class GlobalConfigurationData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(GlobalConfigurationData.class);

	private String configurationId;
	private byte[] data;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of admin's configuration.
	 * Create by sending in the id and string representation of global configuration
	 * @param id the unique id of global configuration.
	 * @param globalconfiguration is the serialized string representation of the global configuration.
	 */
	public GlobalConfigurationData(String configurationId, ConfigurationBase configuration) {
		setConfigurationId(configurationId);
		setConfiguration(configuration);
		if (log.isDebugEnabled()) {
		    log.debug("Created configuration "+configurationId);
		}
	}
	
	public GlobalConfigurationData() { }
	
	//@Id @Column
	public String getConfigurationId() { return configurationId; }
	public void setConfigurationId(String configurationId) { this.configurationId = configurationId; }

	//@Column @Lob
	// Gets the data on raw bytes from the database
	public byte[] getDataUnsafe() { return data; }
	/** DO NOT USE! Stick with setData(HashMap data) instead. */
	public void setDataUnsafe(byte[] data) { this.data = data; }

	/** Gets the serialized object that was stored, as a byte array, in the database.
	 * Deserializes the byte array from the database.
	 * @return Object, typically a LinkedHashMap
	 */
	@Transient
	public Serializable getObjectUnsafe() {
	    try (final ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(getDataUnsafe()));) {
	        return (Serializable) ois.readObject();
	    } catch (IOException e) {
	        log.error("Failed to load Global Configuration as byte[].", e);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
	    return null;
	}
	public void setObjectUnsafe(Serializable data) {
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final ObjectOutputStream oos = new ObjectOutputStream(baos);) {
            oos.writeObject(data);
            setDataUnsafe(baos.toByteArray());
        } catch (IOException e) {
            log.warn("Failed to save Global Configuration as byte[].", e);
        }
	}


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
	public HashMap getData() {
		return JBossUnmarshaller.extractLinkedHashMap(getObjectUnsafe());
	}
	
	@SuppressWarnings("rawtypes")
    private void setData(HashMap data) { setObjectUnsafe(JBossUnmarshaller.serializeObject(data)); }

	/** 
	 * Method that saves the global configuration to database.
	 */
	@SuppressWarnings("rawtypes")
    public void setConfiguration(ConfigurationBase configuration){
		setData((HashMap) configuration.saveData());   
	}

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking so we will not include that in the database protection
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        if (version>=2) {
            // From v2 we use a SHA256 hash of the actually serialized data (raw bytes) as stored in the database
            // This avoids any problems of the getData() object that does not have a good, stable, toString() representation 
            final String dataHash = CertTools.getSHA256FingerprintAsString(getDataUnsafe());
            build.append(getConfigurationId()).append(dataHash);
        } else {
            build.append(getConfigurationId()).append(getData());
        }
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 2;
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

}
