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

package org.ejbca.core.ejb.ca.publisher;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;

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
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.model.ca.publisher.BasePublisher;

/**
 * Representation of a publisher.
 * 
 * @version $Id$
 */
@Entity
@Table(name="PublisherData")
public class PublisherData extends ProtectedData implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(PublisherData.class);

	private BasePublisher publisher = null;

	private int id;
	private String name;
	private int updateCounter;
	private String data;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity Bean holding data of a publisher.
	 *
	 * @return null
	 * @ejb.create-method view-type="local"
	 */
	public PublisherData(int id, String name, BasePublisher publisher) {
		setId(id);
		setName(name);
		setUpdateCounter(0);
		if (publisher != null) {
			setPublisher(publisher);
		}
		log.debug("Created Hard Token Profile " + name);
	}

	public PublisherData() { }

	//@Id @Column
	public int getId() { return id; }
	public void setId(int id) { this.id = id; }

	//@Column
	public String getName() { return name; }
	public void setName(String name) { this.name = name; }

	//@Column
	public int getUpdateCounter() { return updateCounter; }
	public void setUpdateCounter(int updateCounter) { this.updateCounter = updateCounter; }

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
     * Method that gets the cached publisher, if any.
     */
	@Transient
    public BasePublisher getCachedPublisher() {
    	return publisher;
    }

	/**
	 * Method that saves the publisher data to database.
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
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
                log.debug("Publisher data: \n" + baos.toString("UTF8"));
            }
            setData(baos.toString("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
		this.publisher = publisher;
		setUpdateCounter(getUpdateCounter() + 1);
	}

	//
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    public String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getName()).append(getUpdateCounter()).append(getData());
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

	//
	// Search functions. 
	// 

	/** @return the found entity instance or null if the entity does not exist */
	public static PublisherData findById(EntityManager entityManager, int id) {	    
	    return entityManager.find(PublisherData.class, id);
	}

	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static PublisherData findByName(EntityManager entityManager, String name) {
		final Query query = entityManager.createQuery("SELECT a FROM PublisherData a WHERE a.name=:name");
		query.setParameter("name", name);
		return (PublisherData) QueryResultWrapper.getSingleResult(query);
	}

	/** @return return the query results as a List. */
	@SuppressWarnings("unchecked")
    public static List<PublisherData> findAll(EntityManager entityManager) {
		final Query query = entityManager.createQuery("SELECT a FROM PublisherData a");
		return query.getResultList();
	}
}
