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
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.CertTools;

/**
 * Representation of a CA instance.
 * 
 * @version $Id$
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
	
	public static Integer calculateCAId(final String subjectdn){
	    return Integer.valueOf(subjectdn.hashCode());
	}
    
	/**
	 * Entity Bean holding data of a CA.
	 * @param subjectdn
	 * @param name of CA
	 * @param status initial status
	 * @param ca CA to store
	 */
	public CAData(final String subjectdn, final String name, final int status, final CA ca) {
	    setCaId(calculateCAId(subjectdn));
	    setName(name);
	    setSubjectDN(subjectdn);
	    if (ca.getCACertificate() != null) {
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

	/** @return a CA in the form it was saved in the database + regular UpgradableHashMap upgrade-on-load */
    @Transient
    public CA getCA() {
        final LinkedHashMap<Object, Object> dataMap = getDataMap();
        CA ca = null;
        switch (((Integer)(dataMap.get(CA.CATYPE))).intValue()) {
        case CAInfo.CATYPE_X509:
            ca = new X509CA(dataMap, getCaId().intValue(), getSubjectDN(), getName(), getStatus(), getUpdateTimeAsDate(), new Date(getExpireTime()));                    
            break;
        case CAInfo.CATYPE_CVC:
            ca = CvcCA.getInstance(dataMap, getCaId().intValue(), getSubjectDN(), getName(), getStatus(), getUpdateTimeAsDate(), new Date(getExpireTime()));                    
            break;
        }
        return ca;
    }

	/**  Method that converts the CA object to storage representation. */
	@SuppressWarnings({"unchecked"})
    @Transient
    public final void setCA(final CA ca) {
        setDataMap((LinkedHashMap<Object, Object>) ca.saveData());
        setUpdateTime(System.currentTimeMillis());
        // We have to update status as well, because it is kept in it's own database column, but only do that if it was actually provided in the request
        if (ca.getStatus() > 0) {
            setStatus(ca.getStatus());        	
        }
        setName(ca.getName());
        setSubjectDN(ca.getSubjectDN());
        // set expire time, perhaps we have updated the CA certificate
        final Certificate cacert = ca.getCACertificate();
        if (cacert != null) {
            setExpireTime(CertTools.getNotAfter(cacert).getTime());
        }
	}   

	@Transient
	public LinkedHashMap<Object, Object> getDataMap() {
        try {
            java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
            final Map<?, ?> h = (Map<?, ?>)decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            @SuppressWarnings("unchecked")
            final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap(h);
            return dataMap;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);  // No UTF8 would be real trouble
        }
	}

    @Transient
    @SuppressWarnings({"rawtypes", "unchecked"})
	public void setDataMap(final LinkedHashMap<Object, Object> dataMap) {
        try {
            // We must base64 encode string for UTF safety
            final LinkedHashMap<?, ?> a = new Base64PutHashMap();
            a.putAll((LinkedHashMap)dataMap);
            final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
            encoder.writeObject(a);
            encoder.close();
            final String data = baos.toString("UTF8");
            if (log.isDebugEnabled()) {
                log.debug("Saving CA data with length: "+data.length()+" for CA.");
            }
            setData(data);
            setUpdateTime(System.currentTimeMillis());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
	}

	//
	// Start Database integrity protection methods
	//
	
	@Transient
	@Override
	public String getProtectString(final int version) {
		final ProtectionStringBuilder build = new ProtectionStringBuilder(8000);
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
		return getCaId().toString();		
	}
	//
	// End Database integrity protection methods
	//

}
