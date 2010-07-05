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
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Query;
import javax.persistence.Table;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.ejbca.util.GUIDGenerator;

/**
 * Entity Bean representing publisher failure data. Data is stored here when publishing to a publisher fails. Using this data publishing
 * can be tried again. This data bean should not duplicate data completely, but holds this:
 * 
 * - Information needed for scheduling of republishing, such as publish dates, retry counter and last failure message.
 * - Information which is volatile on other places in the database, and we need to publish this data as it was at the time of publishing.
 *   In this case it is UserData, which can change because every user can have several certificates with different DN, the password is re-set
 *   when a certificate is issued etc.
 * - Foreign keys to information which is not volatile.
 *   In this case this is keys to CertificateData and CRLData. For CertificateData we always want to publish the latest information, even if it changed
 *   since we failed to publish. This is so there should be no chance that a revocation is overwritten with a good status if the 
 *   publish events would happen out of order.
 *   
 * @author Tomas Gustavsson
 * @version $Id$
 */
@Entity
@Table(name="PublisherQueueData")
public class PublisherQueueData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(PublisherQueueData.class);

	private String pk;
	private long timeCreated;
	private long lastUpdate;
	private int publishStatus;
	private int tryCounter;
	private int publishType;
	private String fingerprint;
	private int publisherId;
	private String volatileData;	// LOB

    /**
     * @param publishType is one of PublishQueueData.PUBLISH_TYPE_CERT or CRL
     * @return null
     */
    public PublisherQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileData queueData, int publishStatus) {
    	String pk = GUIDGenerator.generateGUID(this); 
		setPk(pk);
		Date now = new Date();
        setTimeCreated(now.getTime());
        setLastUpdate(0);
        setPublishStatus(publishStatus);
        setTryCounter(0);
        setPublishType(publishType);
        setFingerprint(fingerprint);
        setPublisherId(publisherId);
        setPublisherQueueVolatileData(queueData);
        log.debug("Created Publisher queue data " + pk);
    }
    
    public PublisherQueueData() {}

	@Id
	@Column(name="pk")
    public String getPk() { return pk; }
    public void setPk(String pk) { this.pk = pk; }

	@Column(name="timeCreated")
    public long getTimeCreated() { return timeCreated; }
    public void setTimeCreated(long timeCreated) { this.timeCreated = timeCreated; }

	@Column(name="lastUpdate")
    public long getLastUpdate() { return lastUpdate; }
    public void setLastUpdate(long lastUpdate) { this.lastUpdate = lastUpdate; }

    /**
     * PublishStatus is one of org.ejbca.core.model.ca.publisher.PublisherQueueData.STATUS_PENDING, FAILED or SUCCESS.
     */
	@Column(name="publishStatus")
    public int getPublishStatus() { return publishStatus; }
    public void setPublishStatus(int publishStatus) { this.publishStatus = publishStatus; }

	@Column(name="tryCounter")
    public int getTryCounter() { return tryCounter; }
    public void setTryCounter(int tryCounter) { this.tryCounter = tryCounter; }

    /**
     * PublishType is one of org.ejbca.core.model.ca.publisher.PublishQueueData.PUBLISH_TYPE_CERT or CRL
     */
	@Column(name="publishType")
    public int getPublishType() { return publishType; }
    public void setPublishType(int publishType) { this.publishType = publishType; }

    /**
     * Foreign key to certificate of CRL.
     */
	@Column(name="fingerprint")
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

	@Column(name="publisherId")
    public int getPublisherId() { return publisherId; }
    public void setPublisherId(int publisherId) { this.publisherId = publisherId; }

	// DB2: CLOB(100K), Derby: LONG VARCHAR, Informix: TEXT, Ingres: CLOB, MSSQL: TEXT, MySQL: TEXT, Oracle: CLOB, Sapdb: LONG, Sybase: TEXT
	@Column(name="volatileData")
	@Lob
    public String getVolatileData() { return volatileData; }
    public void setVolatileData(String volatileData) { this.volatileData = volatileData; }

    /**
     * Method that returns the PublisherQueueVolatileData data and updates it if necessary.
     * @return VolatileData is optional in publisher queue data
     */
    public PublisherQueueVolatileData getPublisherQueueVolatileData() {
    	PublisherQueueVolatileData ret = null;
    	try {
    		String vd = getVolatileData();
    		if ( (vd != null) && (vd.length() > 0) ) {
    			byte[] databytes = vd.getBytes("UTF8");    			
    			java.beans.XMLDecoder decoder;
    			decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(databytes));
    			HashMap h = (HashMap) decoder.readObject();
    			decoder.close();
    			// Handle Base64 encoded string values
    			HashMap data = new Base64GetHashMap(h);
    			ret = new PublisherQueueVolatileData();
    			ret.loadData(data);
    			if (ret.isUpgraded()) {
    				setPublisherQueueVolatileData(ret);
    			}    		
    		}
    	} catch (UnsupportedEncodingException e) {
    		throw new RuntimeException(e);
    	}
    	return ret;
    }

    /**
     * Method that saves the PublisherQueueData data to database.
     * @param qd is optional in publisher queue data
     */
    public void setPublisherQueueVolatileData(PublisherQueueVolatileData qd) {
    	if (qd != null) {
            // We must base64 encode string for UTF safety
            HashMap a = new Base64PutHashMap();
            a.putAll((HashMap)qd.saveData());
            
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
            encoder.writeObject(a);
            encoder.close();

            try {
                if (log.isDebugEnabled()) {
                    log.debug("PublisherQueueVolatileData: \n" + baos.toString("UTF8"));
                }
                setVolatileData(baos.toString("UTF8"));
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }	
    	}
    }
    
	//
	// Search functions. 
	//

	public static PublisherQueueData findById(EntityManager entityManager, Integer id) {
		return entityManager.find(PublisherQueueData.class,  id);
	}
	
	public static PublisherQueueData findDataByFingerprint(EntityManager entityManager, String fingerprint) {
		Query query = entityManager.createQuery("from PublisherQueueData a WHERE a.fingerprint=:fingerprint");
		query.setParameter("fingerprint", fingerprint);
		return (PublisherQueueData) query.getSingleResult();
	}

	public static Collection<PublisherQueueData> findDataByPublisherIdAndStatus(EntityManager entityManager, int publisherId, int publishStatus) {
		Query query = entityManager.createQuery("from PublisherQueueData a WHERE a.publisherId=:publisherId and a.publishStatus=:publishStatus");
		query.setParameter("publisherId", publisherId);
		query.setParameter("publishStatus", publishStatus);
		return query.getResultList();
	}
}
