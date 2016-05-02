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

package org.ejbca.core.ejb.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
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
import org.cesecore.util.ValueExtractor;
import org.ejbca.core.model.approval.ApprovalDataVO;

/**
 * Representation of approval data used to control request and their approvals.
 * 
 * @version $Id$
 */
@Entity
@Table(name="ApprovalData")
public class ApprovalData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ApprovalData.class);

	private int id;
	private int approvalId;
	private int approvalType;
	private int approvalProfileId;
	private int endEntityProfileId;
	private int cAId;
	private String reqAdminCertIssuerDn;
	private String reqAdminCertSn;
	private int status;
	private String approvalData;
	private String requestData;
	private long requestDate;
	private long expireDate;
	private int remainingApprovals;
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of a approval data.
	 * 
	 * The constructor is responsible for populating all non-nullable fields!
	 */
	public ApprovalData(final int id) {
		setId(id);
		setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);        
		setRequestdate(System.currentTimeMillis());
		log.debug("Created approval with id " + id);
	}

	public ApprovalData() { 
		// used from test code (also required by JPA!)
	}

	/** unique row id */
	//@Id @Column
	public int getId() { return id; }

	/** unique row id */
	public final void setId(final int id) { this.id = id; }

	/**
	 * Constructed from action data as actiontype, admin, username etc. It should
	 * result in the same approvalid if the admin tries to request the same action twice.
	 */
	//@Column
	public int getApprovalid() { return approvalId; }
	/**
	 * Constructed from action data as actiontype, admin, username etc. It should
	 * result in the same approvalid if the admin tries to request the same action twice.
	 */
	public void setApprovalid(int approvalId) { this.approvalId = approvalId; } 

	/**   
	 * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
	 * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
	 */
	//@Column
	public int getApprovaltype() { return approvalType; }
	/**
	 * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
	 * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
	 */
	public void setApprovaltype(int approvalType) { this.approvalType = approvalType; }
	
	/**
     * The related approval profile id
     */
    //@Column
    public int getApprovalProfileId() { return approvalProfileId; }
    /**
     * The related approval profile id     
     */
    public void setApprovalProfileId(int approvalProfileId) { this.approvalProfileId = approvalProfileId; }

	/**
	 * For RA specific approval requests should the related end entity profile id be specified
	 * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
	 */
	//@Column
	public int getEndentityprofileid() { return endEntityProfileId; }
	/**
	 * For RA specific approval requests should the related end entity profile id be specified
	 * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
s	 */
	public void setEndentityprofileid(int endEntityProfileId) { this.endEntityProfileId = endEntityProfileId; }

	/**
	 * For CA specific approval requests should the related ca id be specified
	 * for non ca request should this field be set to ApprovalDataVO.ANY_CA
	 */
	//@Column
	public int getCaid() { return cAId; }
	/**
	 * For CA specific approval requests should the related ca id be specified
	 * for non ca request should this field be set to ApprovalDataVO.ANY_CA    
	 */
	public void setCaid(int cAId) { this.cAId = cAId; }

	/**
	 * The issuerdn of the administrator certificate that generated the request.
	 */
	//@Column
	public String getReqadmincertissuerdn() { return reqAdminCertIssuerDn; }
	/**
	 * The issuerdn of the administrator certificate that generated the request.
	 */
	public void setReqadmincertissuerdn(String reqAdminCertIssuerDn) { this.reqAdminCertIssuerDn = reqAdminCertIssuerDn; }

	/**
	 * The serialnumber of the administrator certificate that generated the request. String in Hex.
	 */
	//@Column
	public String getReqadmincertsn() { return reqAdminCertSn; }
	/**
	 * The serialnumber of the administrator certificate that generated the request. String in Hex.
	 */
	public void setReqadmincertsn(String reqAdminCertSn) { this.reqAdminCertSn = reqAdminCertSn; }

	/**
	 * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, 
	 * STATUS_REJECTED, STATUS_EXPIRED
	 */
	//@Column
	public int getStatus() { return status; }
	/**
	 * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, 
	 * STATUS_REJECTED, STATUS_EXPIRED
	 */
	public void setStatus(int status) { this.status = status; }

	/**
	 * Stringrepresentation of data of approvals made by one or more administrators
	 */
	//@Column @Lob
	public String getApprovaldata() { return approvalData; }

	/**
	 * Stringrepresentation of data of approvals made by one or more administrators
	 */
	public void setApprovaldata(String approvalData) { this.approvalData = approvalData; }

	/**
	 * Data containing information about the request displayed for the approval administrator.
	 */
	//@Column @Lob
	public String getRequestdata() { return requestData; }

	/**
	 * Data containing information about the request displayed for the approval administrator.
	 */
	public void setRequestdata(String requestData) { this.requestData = requestData; }            

	/**
	 * Date the request for approval were added
	 */
	//@Column
	public long getRequestdate() { return requestDate; }
	/**
	 * Date the request for approval were added
	 */
	public void setRequestdate(long requestDate) { this.requestDate = requestDate; }

	/**
	 * Date the request for action or the approval action will expire, Long.MAX_VALUE 
	 * means that the request/approval never expires
	 */
	//@Column
	public long getExpiredate() { return expireDate; }
	/**
	 * Date the request for action or the approval action will expire, Long.MAX_VALUE 
	 * means that the request/approval never expires
	 */
	public void setExpiredate(long expireDate) { this.expireDate = expireDate; }

	/**
	 * Indicates the number of approvals that remains in order to execute the action
	 */
	//@Column
	public int getRemainingapprovals() { return remainingApprovals; }
	/**
	 * Indicates the number of approvals that remains in order to execute the action  
	 */
	public void setRemainingapprovals(int remainingApprovals) { this.remainingApprovals = remainingApprovals; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	@Override
	public String getRowProtection() { return rowProtection; }
	@Override
	public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

	@Transient 
	public Date getRequestDate() {
		return new Date(getRequestdate());
	}

	@Transient 
	public Date getExpireDate() {
		return new Date(getExpiredate());
	}

	/**
	 * Method used to set the expire date of the request
	 */
	public void setExpireDate(final Date expireDate){
		setExpiredate(expireDate.getTime());
	}

	/**
	 * Method that checks if the request or approval have expired
	 * The status is set to expired if it is
	 * @return true of the request or approval have expired
	 */
	public boolean hasRequestOrApprovalExpired() {
		final Date currentDate = new Date();
		boolean retval = false;
		if(currentDate.after(getExpireDate())){
			if(getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL ||
					getStatus() == ApprovalDataVO.STATUS_APPROVED ||
					getStatus() == ApprovalDataVO.STATUS_REJECTED){
				setStatus(ApprovalDataVO.STATUS_EXPIRED);
			}
			retval=true;
		}
		return retval;
	}

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getApprovalid()).append(getApprovaltype()).append(getEndentityprofileid()).append(getCaid()).append(getReqadmincertissuerdn());
        build.append(getReqadmincertsn()).append(getStatus()).append(getApprovaldata()).append(getRequestdata()).append(getRequestdate()).append(getExpiredate()).append(getRemainingapprovals());
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
	public static ApprovalData findById(final EntityManager entityManager, final Integer id) {
		return entityManager.find(ApprovalData.class, id);
	}
	
	/** @return return the query results as a List. */
	@SuppressWarnings("unchecked")
    public static List<ApprovalData> findByApprovalId(final EntityManager entityManager, final int approvalid) {
		final Query query = entityManager.createQuery("SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalId");
		query.setParameter("approvalId", approvalid);
		return query.getResultList();
	}
	
	/** @return return the query results as a List. */
	@SuppressWarnings("unchecked")
    public static List<ApprovalData> findByApprovalIdNonExpired(final EntityManager entityManager, final int approvalid) {
		final Query query = entityManager.createQuery("SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalId AND (a.status>"+ApprovalDataVO.STATUS_EXPIRED+")");
		query.setParameter("approvalId", approvalid);
		return query.getResultList();
	}

	/** @return return the query results as a List<Integer>. */
	@SuppressWarnings("unchecked")
    public static List<Integer> findByApprovalIdsByStatus(final EntityManager entityManager, final int status) {
		final Query query = entityManager.createQuery("SELECT a.approvalid FROM ApprovalData a WHERE a.status=:status");
		query.setParameter("status", status);
		return query.getResultList();
	}
	
	/** @return return the query results as a List. */
    @SuppressWarnings("unchecked")
    public static List<ApprovalData> findByStatusAndApprovalProfile(final EntityManager entityManager, final int status, final int approvalPorfileId) {
        final Query query = entityManager.createQuery("SELECT a FROM ApprovalData a WHERE a.status=:status AND a.approvalProfileId=:approvalProfileId");
        query.setParameter("status", status);
        query.setParameter("approvalProfileId", approvalPorfileId);
        return query.getResultList();
    }
	

	/** @return return the query results as a List<ApprovalData>. */
	public static List<ApprovalData> findByCustomQuery(final EntityManager entityManager, final int index, final int numberofrows, final String customQuery) {
		final List<ApprovalData> ret = new ArrayList<ApprovalData>();
		/* Hibernate on DB2 wont allow us to "SELECT *" in combination with setMaxResults.
		 * Ingres wont let us access a LOB in a List using a native query for all fields.
		 * -> So we will get a list of primary keys and the fetch the whole entities one by one...
		 * 
		 * As a sad little bonus, DB2 native queries returns a pair of {BigInteger, Integer}
		 * where the first value is row and the second is the value.
		 * As another sad little bonus, Oracle native queries returns a pair of {BigDecimal, BigDecimal}
		 * where the first value is the value and the second is the row.
		 */
		final Query query = entityManager.createNativeQuery("SELECT id FROM ApprovalData WHERE " + customQuery);
		query.setFirstResult(index);
		query.setMaxResults(numberofrows);
		@SuppressWarnings("unchecked")
        final List<Object> ids = query.getResultList();
		for (Object object : ids) {
			final int id = ValueExtractor.extractIntValue(object);
			ret.add(entityManager.find(ApprovalData.class, id));
		}
		return ret;
	}
}
