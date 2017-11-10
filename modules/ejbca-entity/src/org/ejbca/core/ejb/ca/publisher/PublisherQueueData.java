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
import java.util.ArrayList;
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
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.GUIDGenerator;
import org.cesecore.util.ValueExtractor;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Entity Bean representing publisher failure data. Data is stored here when
 * publishing to a publisher fails. Using this data publishing can be tried
 * again. This data bean should not duplicate data completely, but holds this:
 * 
 * - Information needed for scheduling of republishing, such as publish dates,
 * retry counter and last failure message. - Information which is volatile on
 * other places in the database, and we need to publish this data as it was at
 * the time of publishing. In this case it is UserData, which can change because
 * every user can have several certificates with different DN, the password is
 * re-set when a certificate is issued etc. - Foreign keys to information which
 * is not volatile. In this case this is keys to CertificateData and CRLData.
 * For CertificateData we always want to publish the latest information, even if
 * it changed since we failed to publish. This is so there should be no chance
 * that a revocation is overwritten with a good status if the publish events
 * would happen out of order.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "PublisherQueueData")
public class PublisherQueueData extends ProtectedData implements Serializable {

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
    private String volatileData;
	private int rowVersion = 0;
	private String rowProtection;

    /**
     * @param publishType
     *            is one of PublishQueueData.PUBLISH_TYPE_CERT or CRL
     * @return null
     */
    public PublisherQueueData(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileInformation queueData, int publishStatus) {
        String pk = GUIDGenerator.generateGUID(this);
        setPk(pk);
        setTimeCreated(System.currentTimeMillis());
        setLastUpdate(0);
        setPublishStatus(publishStatus);
        setTryCounter(0);
        setPublishType(publishType);
        setFingerprint(fingerprint);
        setPublisherId(publisherId);
        setPublisherQueueVolatileData(queueData);
        if (log.isDebugEnabled()) {
            log.debug("Created Publisher queue data " + pk);
        }
    }

    public PublisherQueueData() { }

    //@Id @Column
    public String getPk() { return pk; }
    public void setPk(String pk) { this.pk = pk; }

    //@Column
    public long getTimeCreated() { return timeCreated; }
    public void setTimeCreated(long timeCreated) { this.timeCreated = timeCreated; }

    //@Column
    public long getLastUpdate() { return lastUpdate; }
    public void setLastUpdate(long lastUpdate) { this.lastUpdate = lastUpdate; }

    /**
     * PublishStatus is one of
     * org.ejbca.core.model.ca.publisher.PublisherQueueData.STATUS_PENDING,
     * FAILED or SUCCESS.
     */
    //@Column
    public int getPublishStatus() { return publishStatus; }
    public void setPublishStatus(int publishStatus) { this.publishStatus = publishStatus; }

    //@Column
    public int getTryCounter() { return tryCounter; }
    public void setTryCounter(int tryCounter) { this.tryCounter = tryCounter; }

    /**
     * PublishType is one of
     * org.ejbca.core.model.ca.publisher.PublishQueueData.PUBLISH_TYPE_CERT or
     * CRL
     */
    //@Column
    public int getPublishType() { return publishType; }
    public void setPublishType(int publishType) { this.publishType = publishType; }

    /**
     * Foreign key to certificate of CRL.
     */
    //@Column
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }

    //@Column
    public int getPublisherId() { return publisherId; }
    public void setPublisherId(int publisherId) { this.publisherId = publisherId; }

    //@Column @Lob
    public String getVolatileData() { return volatileData; }
    public void setVolatileData(String volatileData) { this.volatileData = volatileData; }

    //@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

    /**
     * Method that returns the PublisherQueueVolatileData data and updates it if
     * necessary.
     * 
     * @return VolatileData is optional in publisher queue data
     */
    @Transient
    public PublisherQueueVolatileInformation getPublisherQueueVolatileData() {
        PublisherQueueVolatileInformation ret = null;
        try {
            String vd = getVolatileData();
            if ((vd != null) && (vd.length() > 0)) {
                byte[] databytes = vd.getBytes("UTF8");
                java.beans.XMLDecoder decoder;
                decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(databytes));
                HashMap<?, ?> h = (HashMap<?, ?>) decoder.readObject();
                decoder.close();
                // Handle Base64 encoded string values
                HashMap<?, ?> data = new Base64GetHashMap(h);
                ret = new PublisherQueueVolatileInformation();
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
     * 
     * @param qd
     *            is optional in publisher queue data
     */
    @SuppressWarnings("unchecked")
    public void setPublisherQueueVolatileData(PublisherQueueVolatileInformation qd) {
        if (qd != null) {
            // We must base64 encode string for UTF safety
            HashMap<Object, Object> a = new Base64PutHashMap();
            a.putAll((HashMap<Object, Object>) qd.saveData());

            // typical size of XML is something like 250-400 chars
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream(400); 
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
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getPk()).append(getTimeCreated()).append(getLastUpdate()).append(getPublishStatus());
        build.append(getTryCounter()).append(getPublishType()).append(getFingerprint()).append(getPublisherId()).append(getVolatileData());
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
        return getPk();
    }

    //
    // End Database integrity protection methods
    //

    //
    // Search functions. 
    //

    /** @return the found entity instance or null if the entity does not exist */
    public static PublisherQueueData findByPk(EntityManager entityManager, String pk) {
    	return entityManager.find(PublisherQueueData.class, pk);
    }
    
    /** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<PublisherQueueData> findDataByFingerprint(EntityManager entityManager, String fingerprint) {
    	final Query query = entityManager.createQuery("SELECT a FROM PublisherQueueData a WHERE a.fingerprint=:fingerprint");
    	query.setParameter("fingerprint", fingerprint);
    	return query.getResultList();
    }

    /** 
     * @param maxRows If set > 0, limits the number of rows fetched.
     * 
     * @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<PublisherQueueData> findDataByPublisherIdAndStatus(EntityManager entityManager, int publisherId, int publishStatus, int maxRows) {
    	final Query query = entityManager.createQuery("SELECT a FROM PublisherQueueData a WHERE a.publisherId=:publisherId AND a.publishStatus=:publishStatus");
    	query.setParameter("publisherId", publisherId);
    	query.setParameter("publishStatus", publishStatus);
    	if(maxRows > 0 ) {
    		query.setMaxResults(maxRows);
    	}
    	return query.getResultList();
    }

	/** @return return the count. */
	public static long findCountOfPendingEntriesForPublisher(EntityManager entityManager, int publisherId) {
		Query query = entityManager.createQuery("SELECT COUNT(a) FROM PublisherQueueData a WHERE a.publisherId=:publisherId AND publishStatus=" + PublisherConst.STATUS_PENDING);
		query.setParameter("publisherId", publisherId);
		return ((Long)query.getSingleResult()).longValue();	// Always returns a result
	}

	/**
	 * @return the count of pending entries for a publisher in the specified intervals.
	 */
	@SuppressWarnings("unchecked")
    public static List<Integer> findCountOfPendingEntriesForPublisher(EntityManager entityManager, int publisherId, int[] lowerBounds, int[] upperBounds) {
    	final StringBuilder sql = new StringBuilder();
    	long now = System.currentTimeMillis();
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
    	final Query query = entityManager.createNativeQuery(sql.toString());
    	List<?> resultList = query.getResultList();
        if (log.isDebugEnabled()) {
            log.debug("findCountOfPendingEntriesForPublisher result: "+resultList.toString());              
        }
    	List<Integer> returnList;
    	// Derby returns Integers, MySQL returns BigIntegers, Oracle returns BigDecimal
    	if (resultList.size()==0) {
    		returnList = new ArrayList<Integer>();
    	} else if (resultList.get(0) instanceof Integer) {
    		returnList = (List<Integer>) resultList;	// This means we can return it in it's current format
    	} else {
    		returnList = new ArrayList<Integer>();
    		for (Object o : resultList) {
    			returnList.add(ValueExtractor.extractIntValue(o));
    		}
    	}
		return returnList;
	}
}
