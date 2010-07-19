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

package org.ejbca.core.ejb.ra.userdatasource;

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
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.util.Base64PutHashMap;

/**
 * Representation of a user data source.
 */
@Entity
@Table(name="UserDataSourceData")
public class UserDataSourceData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(UserDataSourceData.class);

    private BaseUserDataSource userdatasource = null;

    private Integer id;
    private String name;
    private int updateCounter;
    private String data;
    
    /**
     * Entity holding data of a userdatasource.
     * @throws UnsupportedEncodingException 
     */
    public UserDataSourceData(Integer id, String name, BaseUserDataSource userdatasource) throws UnsupportedEncodingException {
        setId(id);
        setName(name);
        this.setUpdateCounter(0);
        if (userdatasource != null) {
            setUserDataSource(userdatasource);
        }
        log.debug("Created User Data Source " + name);
    }

    public UserDataSourceData()  { }

    /** Primary key. */
    @Id
    @Column(name="id")
    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }

    /** Name of the user data source. */
    @Column(name="name")
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    /** Counter incremented each update used to check if a user data source proxy class should update its data. */
    @Column(name="updateCounter")
    public int getUpdateCounter() { return updateCounter; }
    public void setUpdateCounter(int updateCounter) { this.updateCounter = updateCounter; }

    /** Data saved concerning the user data source. */
	// DB2: CLOB(100K) [100K (2GBw/o)], Derby: LONG VARCHAR [32,700 characters], Informix: TEXT (2147483648 b?), Ingres: , MSSQL: TEXT [2,147,483,647 bytes], MySQL: TEXT [65535 chars], Oracle: CLOB [4G chars], Sybase: TEXT [2,147,483,647 chars]  
    @Column(name="data", length=32700)
    @Lob
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    /**
     * Method that returns the cached UserDataSource.
     */
    @Transient
    public BaseUserDataSource getCachedUserDataSource() {
    	return userdatasource;
    }

    /**
     * Method that saves the userdatasource data to database.
     * @throws UnsupportedEncodingException 
     */
    public void setUserDataSource(BaseUserDataSource userdatasource) {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)userdatasource.saveData());
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
        this.userdatasource = userdatasource;
        setUpdateCounter(getUpdateCounter() + 1);
    }
    
    //
	//  Search functions. 
	//

    public static UserDataSourceData findById(EntityManager entityManager, int id) {
    	return entityManager.find(UserDataSourceData.class,  id);
    }

    public static UserDataSourceData findByName(EntityManager entityManager, String name) {
    	Query query = entityManager.createQuery("from UserDataSourceData a WHERE a.name=:name");
    	query.setParameter("name", name);
    	return (UserDataSourceData) query.getSingleResult();
    }
    
    public static Collection<UserDataSourceData> findAll(EntityManager entityManager) {
    	Query query = entityManager.createQuery("from UserDataSourceData a");
    	return query.getResultList();
    }
}
