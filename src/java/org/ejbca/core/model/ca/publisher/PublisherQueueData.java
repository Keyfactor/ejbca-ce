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
 
package org.ejbca.core.model.ca.publisher;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.apache.log4j.Logger;


/**
 * Value object holding the data contained in a PublisherQueueData record in the database. 
 *
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class PublisherQueueData implements java.io.Serializable {

    private static final Logger log = Logger.getLogger(PublisherQueueData.class);

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = 101L;
    
    // private fields.
    private String pk;
	private Date timeCreated;
    private Date lastUpdate;
    /** PublisherQueueData.STATUS_SUCCESS etc */
    private int publishStatus;
    private int tryCounter;
    /** PublisherQueueData.PUBLISH_TYPE_CERT etc */
    private int publishType;
    private String fingerprint;
    private int publisherId;
    private PublisherQueueVolatileData volatileData;
            
    
    // Public constants

    // Public methods.
    
	public PublisherQueueData(String pk, Date timeCreated, Date lastUpdate,
			int publishStatus, int tryCounter, int publishType, String fingerprint,
			int publisherId, PublisherQueueVolatileData volatileData) {
		super();
		this.pk = pk;
		this.timeCreated = timeCreated;
		this.lastUpdate = lastUpdate;
		this.publishStatus = publishStatus;
		this.tryCounter = tryCounter;
		this.publishType = publishType;
		this.fingerprint = fingerprint;
		this.publisherId = publisherId;
		this.volatileData = volatileData;
	}
    
    public int getPublishType() {
		return publishType;
	}

	public void setPublishType(int publishType) {
		this.publishType = publishType;
	}

	public String getPk() {
		return pk;
	}
	public void setPk(String pk) {
		this.pk = pk;
	}
	public Date getTimeCreated() {
		return timeCreated;
	}
	public void setTimeCreated(Date timeCreated) {
		this.timeCreated = timeCreated;
	}
	public Date getLastUpdate() {
		return lastUpdate;
	}
	public void setLastUpdate(Date lastUpdate) {
		this.lastUpdate = lastUpdate;
	}
	public int getPublishStatus() {
		return publishStatus;
	}
	public void setPublishStatus(int publishStatus) {
		this.publishStatus = publishStatus;
	}
	public int getTryCounter() {
		return tryCounter;
	}
	public void setTryCounter(int tryCounter) {
		this.tryCounter = tryCounter;
	}
	public String getFingerprint() {
		return fingerprint;
	}
	public void setFingerprint(String fingerprint) {
		this.fingerprint = fingerprint;
	}
	public int getPublisherId() {
		return publisherId;
	}
	public void setPublisherId(int publisherId) {
		this.publisherId = publisherId;
	}
	public PublisherQueueVolatileData getVolatileData() {
		return volatileData;
	}
	public void setVolatileData(PublisherQueueVolatileData volatileData) {
		this.volatileData = volatileData;
	}
    
	/** @return return the count. */
	public static long findCountOfPendingEntriesForPublisher(EntityManager entityManager, int publisherId) {
		Query query = entityManager.createQuery("SELECT COUNT(a) FROM PublisherQueueData a WHERE a.publisherId=:publisherId AND publishStatus=" + PublisherConst.STATUS_PENDING);
		query.setParameter("publisherId", publisherId);
		return ((Long)query.getSingleResult()).longValue();
	}

	/**
	 * @return the count of pending entries for a publisher in the specified intervals.
	 */
	public static List<BigInteger> findCountOfPendingEntriesForPublisher(EntityManager entityManager, int publisherId, int[] lowerBounds, int[] upperBounds) {
    	StringBuilder sql = new StringBuilder();
    	long now = new Date().getTime();
    	for(int i = 0; i < lowerBounds.length; i++) {
    		sql.append("SELECT COUNT(*) FROM PublisherQueueData where publisherId=");
    		sql.append(publisherId);
    		sql.append(" AND publishStatus=");
    		sql.append(PublisherConst.STATUS_PENDING);
    		if(lowerBounds[i] > 0) {
	    		sql.append(" AND timeCreated < ");
	    		sql.append(now - 1000 * lowerBounds[i]);
    		}
    		if(upperBounds[i] > 0) {
	    		sql.append(" AND timeCreated > ");
	    		sql.append(now - 1000 * upperBounds[i]);
    		}
    		if(i < lowerBounds.length-1) {
    			sql.append(" UNION ALL ");
    		}
    	}
    	if (log.isDebugEnabled()) {
    		log.debug("findCountOfPendingEntriesForPublisher executing SQL: "+sql.toString());    			
		}
    	Query query = entityManager.createNativeQuery(sql.toString());
		return query.getResultList();
	}
}
