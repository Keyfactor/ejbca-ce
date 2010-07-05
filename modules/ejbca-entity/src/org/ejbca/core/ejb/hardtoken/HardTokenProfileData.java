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

package org.ejbca.core.ejb.hardtoken;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashMap;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.util.Base64PutHashMap;

/**
 * Representation of a hard token profile.
 * 
 * @version $Id$
 */
@Entity
@Table(name="HardTokenProfileData")
public class HardTokenProfileData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(HardTokenProfileData.class);

	private Integer id;
	private String name;
	private int updateCounter;
	private String data;

	/**
	 * Entity holding data of a hard token profile.
	 */
	public HardTokenProfileData(Integer id, String name, HardTokenProfile profile) {
		setId(id);
		setName(name);
		setUpdateCounter(0);
		if (profile != null) {
			setHardTokenProfile(profile);
		}
		log.debug("Created Hard Token Profile "+ name );
	}
	
	public HardTokenProfileData() { }

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

	// DB2: CLOB(1M), Derby: CLOB, Informix: TEXT, Ingres: CLOB, MSSQL: TEXT, MySQL: LONGTEXT, Oracle: CLOB, Sapdb: LONG, Sybase: TEXT
	@Column(name="data", length=1*1024*1024)
	@Lob
	public String getData() { return data; }
	public void setData(String data) { this.data = data; }

	/**
	 * Method that saves the hard token profile data to database.
	 */
	@Transient
	public void setHardTokenProfile(HardTokenProfile hardtokenprofile) {
		// We must base64 encode string for UTF safety
		HashMap a = new Base64PutHashMap();
		a.putAll((HashMap)hardtokenprofile.saveData());
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
		encoder.writeObject(a);
		encoder.close();
		try {
            if (log.isDebugEnabled()) {
            	if (baos.size() < 10000) {
                    log.debug("Profiledata: \n" + baos.toString("UTF8"));            		
            	} else {
            		log.debug("Profiledata larger than 10000 bytes, not displayed.");
            	}
            }
			setData(baos.toString("UTF8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		setUpdateCounter(getUpdateCounter() +1);
	}
	
	//
    // Search functions. 
    //

    public static HardTokenProfileData findByPK(EntityManager entityManager, Integer pk) {
    	return entityManager.find(HardTokenProfileData.class,  pk);
    }

    public static HardTokenProfileData findByName(EntityManager entityManager, String name) {
    	Query query = entityManager.createQuery("from HardTokenProfileData a WHERE a.name=:name");
    	query.setParameter("name", name);
    	return (HardTokenProfileData) query.getSingleResult();
    }
    
    public static Collection<HardTokenProfileData> findAll(EntityManager entityManager) {
    	Query query = entityManager.createQuery("from HardTokenProfileData a");
    	return query.getResultList();
    }
}
