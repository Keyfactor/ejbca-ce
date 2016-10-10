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

package org.ejbca.core.ejb.services;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * Representation of a service configuration used by the monitoring services framework.
 * 
 * @version $Id$
 */
@Entity
@Table(name="ServiceData")
public class ServiceData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ServiceData.class);

	private int id;
	private String name;
	private long runTimeStamp;
	private long nextRunTimeStamp;
	private String data;
	private int rowVersion = 0;
	private String rowProtection;

    /**
     * Entity Bean holding data of a service configuration.
     */
    public ServiceData(int id, String name, ServiceConfiguration serviceConfiguration) {
        setId(id);
        setName(name);
        setNextRunTimeStamp(0); // defaults to 0 until we activate the service
        setRunTimeStamp(0); // when created the service has never run yet
        if (serviceConfiguration != null) {
        	setServiceConfiguration(serviceConfiguration);
        }
        log.debug("Created Service Configuration " + name);
    }
    
    public ServiceData() { }

    /** Primary key. */
    //@Id @Column
	public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    /** Name of the service. */
    //@Column
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return runTimeStamp the time the was running last time
     */
    //@Column
    public long getRunTimeStamp() { return runTimeStamp; }
    public void setRunTimeStamp(long runTimeStamp) { this.runTimeStamp = runTimeStamp; }

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return nextRunTimeStamp the time the service will run next time
     */
    //@Column
    public long getNextRunTimeStamp() { return nextRunTimeStamp; }
    public void setNextRunTimeStamp(long nextRunTimeStamp) { this.nextRunTimeStamp = nextRunTimeStamp; }

    /** Data saved concerning the service. */
    //@Column @Lob
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    //@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    /**
     * Method that returns the service configuration data and updates it if necessary.
     */
    @Transient
    public ServiceConfiguration getServiceConfiguration() {
    	java.beans.XMLDecoder decoder;
    	try {
    		decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
    	} catch (UnsupportedEncodingException e) {
    		throw new RuntimeException(e);
    	}
    	HashMap<?, ?> h = (HashMap<?, ?>) decoder.readObject();
    	decoder.close();
    	// Handle Base64 encoded string values
    	HashMap<?, ?> data = new Base64GetHashMap(h);
    	float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
    	ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
    	serviceConfiguration.loadData(data);
    	if ( ((serviceConfiguration != null) && (Float.compare(oldversion, serviceConfiguration.getVersion()) != 0))) {
    		// Upgrade in version 4 of ServiceConfiguration. If we do not have nextRunTimeStamp and runTimeStamp set in
    		// the database, but we have them in serviceConfiguration, we will simply copy the values over.
    		// After this we will not use the values in ServiceConfiguration any more 
    		final String NEXTRUNTIMESTAMP = "NEXTRUNTIMESTAMP";
    		final String OLDRUNTIMESTAMP = "OLDRUNTIMESTAMP";
    		if ((getNextRunTimeStamp() == 0) && (data.get(NEXTRUNTIMESTAMP) != null)) {
    			final long nextRunTs = ((Long) data.get(NEXTRUNTIMESTAMP)).longValue();
    			log.debug("Upgrading nextRunTimeStamp to "+nextRunTs);
    			setNextRunTimeStamp(nextRunTs);
    		}
    		if ((getRunTimeStamp() == 0) && (data.get(OLDRUNTIMESTAMP) != null)) {
    			final long runTs = ((Long) data.get(OLDRUNTIMESTAMP)).longValue();
    			log.debug("Upgrading runTimeStamp to "+runTs);
    			setRunTimeStamp(runTs);
    		}
    		setServiceConfiguration(serviceConfiguration);
    	}
    	return serviceConfiguration;
    }

    /**
     * Method that saves the service configuration data to database.
     */
    @SuppressWarnings("unchecked")
    public void setServiceConfiguration(ServiceConfiguration serviceConfiguration) {
        // We must base64 encode string for UTF safety
        HashMap<Object, Object> a = new Base64PutHashMap();
        a.putAll((HashMap<Object, Object>)serviceConfiguration.saveData());
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
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getName()).append(getData());
        // runTimeStamp and nextRunTimeStamp are deliberately excluded from this so that they can be updated
        // efficiently in method updateTimestamps below. 
        // This causes a slight security risk of denial of service, since the runtimestamp can be modified to manipulate
        // how services run. The EJB timer itself is not stored here though, and with other monitoring that the system/CRLs etc
        // are working it should not be seen as a great security risk. No security vital parts can be modified by altering these values.
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
        return String.valueOf(getId());
    }

    //
    // End Database integrity protection methods
    //

	/** @return true if a service with the old timestamps existed (a.runTimeStamp=:oldRunTimeStamp AND a.nextRunTimeStamp=:oldNextRunTimeStamp) and was updated */
	public static boolean updateTimestamps(EntityManager entityManager, Integer id, long oldRunTimeStamp, long oldNextRunTimeStamp, long newRunTimeStamp, long newNextRunTimeStamp) {
		Query query = entityManager.createQuery("UPDATE ServiceData a SET a.runTimeStamp=:newRunTimeStamp, a.nextRunTimeStamp=:newNextRunTimeStamp"
				+ " WHERE a.id=:id AND a.runTimeStamp=:oldRunTimeStamp AND a.nextRunTimeStamp=:oldNextRunTimeStamp");
		query.setParameter("newRunTimeStamp", newRunTimeStamp);
		query.setParameter("newNextRunTimeStamp", newNextRunTimeStamp);
		query.setParameter("id", id);
		query.setParameter("oldRunTimeStamp", oldRunTimeStamp);
		query.setParameter("oldNextRunTimeStamp", oldNextRunTimeStamp);
		return query.executeUpdate() == 1;
	}
}
