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
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.util.Base64PutHashMap;

/**
 * Representation of a publisher.
 */
@Entity
@Table(name="PublisherData")
public class PublisherData implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(PublisherData.class);

	private BasePublisher publisher = null;

	private Integer id;
	private String name;
	private int updateCounter;
	private String data;

	@Id
	@Column(name="id")
	public Integer getId() { return id; }
	public void setId(Integer id) { this.id = id; }

	@Column(name="name")
	public String getName() { return name; }
	public void setName(String name) { this.name = name; }

	@Column(name="updateCounter", nullable=false)
	public int getUpdateCounter() { return updateCounter; }
	public void setUpdateCounter(int updateCounter) { this.updateCounter = updateCounter; }

	// DB2: CLOB(100K) [100K (2GBw/o)], Derby: LONG VARCHAR [32,700 characters], Informix: TEXT (2147483648 b?), Ingres: CLOB [2GB], MSSQL: TEXT [2,147,483,647 bytes], MySQL: TEXT [65535 chars], Oracle: CLOB [4G chars], Sybase: TEXT [2,147,483,647 chars]  
	@Column(name="data", length=32700)
	@Lob
	public String getData() { return data; }
	public void setData(String data) { this.data = data; }

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
            throw new RuntimeException(e);
        }
		this.publisher = publisher;
		setUpdateCounter(getUpdateCounter() + 1);
	}

	/**
	 * Entity Bean holding data of a publisher.
	 *
	 * @return null
	 * @ejb.create-method view-type="local"
	 */
	public PublisherData(Integer id, String name, BasePublisher publisher) {
		setId(id);
		setName(name);
		this.setUpdateCounter(0);
		if (publisher != null) {
			setPublisher(publisher);
		}
		log.debug("Created Hard Token Profile " + name);
	}

	public PublisherData() { }

	//
	// Search functions. 
	// 

	/** @return the found entity instance or null if the entity does not exist */
	public static PublisherData findById(EntityManager entityManager, Integer id) {	    
	    return entityManager.find(PublisherData.class, id);
	}

	/**
	 * @throws NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static PublisherData findByName(EntityManager entityManager, java.lang.String name) {
		PublisherData ret = null;
		try {
			Query query = entityManager.createQuery("SELECT a FROM PublisherData a WHERE a.name=:name");
			query.setParameter("name", name);
			ret = (PublisherData) query.getSingleResult();
		} catch (NoResultException e) {
		}
		return ret;
	}

	/** @return return the query results as a List. */
	public static List<PublisherData> findAll(EntityManager entityManager) {
		Query query = entityManager.createQuery("SELECT a FROM PublisherData a");
		return query.getResultList();
	}
}
