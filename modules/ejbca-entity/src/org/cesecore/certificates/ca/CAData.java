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
package org.cesecore.certificates.ca;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
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
import org.cesecore.certificates.ca.internal.CACacheManager;
import org.cesecore.certificates.util.CertTools;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.QueryResultWrapper;

/**
 * Representation of a CA instance.
 * 
 * Based on EJBCA's org.ejbca.core.ejb.ca.caadmin.CAData (probably r11168)
 * 
 * @version $Id: CAData.java 809 2011-05-17 15:21:27Z mikek $
 */
@Entity
@Table(name="CAData")
public class CAData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CAData.class);

	private Integer cAId;
	private String name;
	private String subjectDN;
	private int status = 0;			// not null, we need a default
	private long expireTime = 0;	// not null, we need a default
	private long updateTime = 0;	// not null, we need a default
	private String data;
	private int rowVersion = 0;		// not null, we need a default
	private String rowProtection;

	/**
	 * Entity Bean holding data of a CA.
	 * @param subjectdn
	 * @param name of CA
	 * @param status initial status
	 * @param ca CA to store
	 */
	public CAData(final String subjectdn, final String name, final int status, final CA ca) {
		try {
    		setCaId(Integer.valueOf(subjectdn.hashCode()));
    		setName(name);
    		setSubjectDN(subjectdn);
    		if (ca.getCertificateChain().size() != 0) {
    			final Certificate cacert = ca.getCACertificate();
    			setExpireTime(CertTools.getNotAfter(cacert).getTime());  
    			ca.setExpireTime(CertTools.getNotAfter(cacert)); 
    		}  
    		// Set status, because it can occur in the ca object as well, but we think the one passed as argument here is what
    		// is desired primarily, so make sure we set that
    		ca.setStatus(status);        
    		setCA(ca);
    		if (log.isDebugEnabled()) {
    			log.debug("Created CA "+ name);
    		}
		} catch(java.io.UnsupportedEncodingException e) {
			log.error("CAData caught exception trying to create: ", e);
			throw new RuntimeException(e.toString());
		}
	}
	
	public CAData() { }
	
	//@Id @Column
	public Integer getCaId() { return cAId; }
	public final void setCaId(final Integer cAId) { this.cAId = cAId; }

	//@Column
	public String getName() { return name; }
	public void setName(String name) { this.name = name; }

	//@Column
	public String getSubjectDN() { return subjectDN; }
	public void setSubjectDN(String subjectDN) { this.subjectDN = subjectDN; }

	//@Column
	public int getStatus() { return status; }
	public void setStatus(int status) { this.status = status; }

	//@Column
	public long getExpireTime() { return expireTime; }
	public void setExpireTime(long expireTime) { this.expireTime = expireTime; }

	/** When was this CA updated in the database */
	//@Column
	public long getUpdateTime() { return updateTime; }
	public void setUpdateTime(long updateTime){ this.updateTime = updateTime; }

	//@Column @Lob
	public String getData() { return data; }
	public void setData(String data) { this.data = data; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	public Date getUpdateTimeAsDate() {
		return new Date(getUpdateTime());
	}

	/** 
	 * Method that retrieves the CA from the database.
     * @return CA
     * @throws java.io.UnsupportedEncodingException
     * @throws IllegalKeyStoreException 
	 */
	@Transient
	public CA getCA() throws java.io.UnsupportedEncodingException, IllegalCryptoTokenException {
    	// Because get methods are marked as read-only above, this method will actually not be able to upgrade
    	// use upgradeCA above for that.
		// TODO: Mark as read only?
    	return readAndUpgradeCAInternal();
	}

    public void upgradeCA() throws java.io.UnsupportedEncodingException, IllegalCryptoTokenException {
    	readAndUpgradeCAInternal();
    }

    /** We have an internal method for this read operation with a side-effect. 
     * This is because getCA() is a read-only method, so the possible side-effect of upgrade will not happen,
     * and therefore this internal method can be called from another non-read-only method, upgradeCA().
     * @return CA
     * @throws java.io.UnsupportedEncodingException
     * @throws IllegalKeyStoreException
     */
    private final CA readAndUpgradeCAInternal() throws java.io.UnsupportedEncodingException, IllegalCryptoTokenException {
        CA ca = null;
        // First check if we already have a cached instance of the CA
        ca = CACacheManager.instance().getAndUpdateCA(getCaId().intValue(), getStatus(), getExpireTime(), getName(), getSubjectDN());
        boolean isUpdated = false;
        if (ca != null) {
        	if (log.isDebugEnabled()) {
        		log.debug("Found CA ('"+ca.getName()+"', "+getCaId().intValue()+") in cache.");
        	}
        	final long update = ca.getCAInfo().getUpdateTime().getTime();
        	final long t = getUpdateTime();
        	//log.debug("updateTime from ca = "+update);
        	//log.debug("updateTime from db = "+t);
        	if (update < t) {
            	if (log.isDebugEnabled()) {
            		log.debug("CA '"+ca.getName()+"' has been updated in database, need to refresh cache");
            	}
        		isUpdated = true;
        	}
        }
        if ( (ca == null) || isUpdated) {
        	if (log.isDebugEnabled()) {
        		log.debug("Re-reading CA from database: "+getCaId().intValue());
        	}
        	final java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
        	final LinkedHashMap h = (LinkedHashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            final LinkedHashMap<Object, Object> data = new Base64GetHashMap(h);
            
            // If CA-data is upgraded we want to save the new data, so we must get the old version before loading the data 
            // and perhaps upgrading
            final float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
            switch(((Integer)(data.get(CA.CATYPE))).intValue()){
                case CAInfo.CATYPE_X509:
                    ca = new X509CA(data, getCaId().intValue(), getSubjectDN(), getName(), getStatus(), getUpdateTimeAsDate(), new Date(getExpireTime()));                    
                    break;
                case CAInfo.CATYPE_CVC:
                    ca = new CVCCA(data, getCaId().intValue(), getSubjectDN(), getName(), getStatus(), getUpdateTimeAsDate());                    
                    break;
            }
            final boolean upgradedExtendedService = ca.upgradeExtendedCAServices();
            // Compare old version with current version and save the data if there has been a change
            if ( ((ca != null) && (Float.compare(oldversion, ca.getVersion()) != 0)) || upgradedExtendedService) {
            	// Make sure we upgrade the CAToken as well, if needed
                ca.getCAToken();
                setCA(ca);
                log.debug("Stored upgraded CA ('"+ca.getName()+"', "+getCaId().intValue()+") with version "+ca.getVersion());
            }
            // We have to do the same if CAToken was upgraded
            // Add CA to the cache
            CACacheManager.instance().addCA(getCaId().intValue(), ca);
        }
        return ca;              
    }

	/** 
	 * Method that saves the CA to database.
	 * @ejb.interface-method
	 */
	public final void setCA(final CA ca) throws UnsupportedEncodingException {
        // We must base64 encode string for UTF safety
		final LinkedHashMap a = new Base64PutHashMap();
        a.putAll((LinkedHashMap)ca.saveData());
        
        final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        final String data = baos.toString("UTF8");
        if (log.isDebugEnabled()) {
        	log.debug("Saving CA data with length: "+data.length()+" for CA '"+ca.getName()+"'.");
        }
        setData(data);
        setUpdateTime(System.currentTimeMillis());
        // We have to update status as well, because it is kept in it's own database column, but only do that if it was actually provided in the request
        if (ca.getStatus() > 0) {
            setStatus(ca.getStatus());        	
        }
        // remove the CA from the cache to force an update the next time we load it
        CACacheManager.instance().removeCA(getCaId().intValue());
        // .. and we try to load it right away
        try {
			readAndUpgradeCAInternal();
		} catch (IllegalCryptoTokenException e) {
			// Ok.. so we failed after all.. try loading it next time so the error is displayed as it used to..
	        CACacheManager.instance().removeCA(getCaId().intValue());
		}
	}   

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static CAData findById(final EntityManager entityManager, final Integer cAId) {
		return entityManager.find(CAData.class, cAId);
	}
	
	/**
	 * @throws CADoesntExistsException if the entity does not exist
	 * @return the found entity instance
	 */
	public static CAData findByIdOrThrow(final EntityManager entityManager, final Integer cAId) throws CADoesntExistsException {
		final CAData ret = findById(entityManager, cAId);
		if (ret == null) {
			throw new CADoesntExistsException("CA id: " + cAId);
		}
		return ret;
	}
	
	/**
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance or null if the entity does not exist
	 */
	public static CAData findByName(final EntityManager entityManager, final String name) {
		final Query query = entityManager.createQuery("SELECT a FROM CAData a WHERE a.name=:name");
		query.setParameter("name", name);
		return (CAData) QueryResultWrapper.getSingleResult(query);
	}

	/**
	 * @throws CADoesntExistsException if the entity does not exist
	 * @throws javax.persistence.NonUniqueResultException if more than one entity with the name exists
	 * @return the found entity instance
	 */
	public static CAData findByNameOrThrow(final EntityManager entityManager, final String name) throws CADoesntExistsException {
		final CAData ret = findByName(entityManager, name);
		if (ret == null) {
			throw new CADoesntExistsException("CA name: " + name);
		}
		return ret;
	}

	/** @return return the query results as a List<CAData>. */
	public static List<CAData> findAll(final EntityManager entityManager) {
		final Query query = entityManager.createQuery("SELECT a FROM CAData a");
		return query.getResultList();
	}

	/** @return return the query results as a List<Integer>. */
	public static List<Integer> findAllCaIds(final EntityManager entityManager) {
		final Query query = entityManager.createQuery("SELECT a.caId FROM CAData a");
		return query.getResultList();
	}
	
	//
	// Start Database integrity protection methods
	//
	
	@Transient
	@Override
	protected String getProtectString(final int version) {
		StringBuilder build = new StringBuilder(8000);
		// What is important to protect here is the data that we define
		// rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
		build.append(getCaId()).append(getName()).append(getSubjectDN()).append(getStatus()).append(getExpireTime()).append(getUpdateTime()).append(getData());
		if (log.isDebugEnabled()) {
			// Some profiling
			if (build.length() > 8000) {
				log.debug("CAData.getProtectString gives size: "+build.length());
			}
		}
		return build.toString();
	}

	@Transient
	@Override
	protected int getProtectVersion() {
		return 1;
	}

	@PrePersist
	@PreUpdate
	@Transient
	@Override
	protected void protectData() {
		super.protectData();
	}
	
	@PostLoad
	@Transient
	@Override
	protected void verifyData() {
		super.verifyData();
	}

	@Override 
	@Transient
	protected String getRowId() {
		return getCaId().toString();		
	}
	//
	// End Database integrity protection methods
	//

}
