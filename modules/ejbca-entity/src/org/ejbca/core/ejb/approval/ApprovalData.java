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

package org.ejbca.core.ejb.approval;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataUtil;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.ValueExtractor;

/**
 * Representation of approval data used to control request and their approvals.
 * 
 * @version $Id$
 */
@Entity
@Table(name="ApprovalData")
public class ApprovalData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ApprovalData.class);

	private int id;
	private int approvalid;
	private int approvaltype;
	private int endentityprofileid;
	private int caid;
	private String reqadmincertissuerdn;
	private String reqadmincertsn;
	private int status;
	private String approvaldata;
	private String requestdata;
	private long requestdate;
	private long expiredate;
	private int remainingapprovals;	
	private int rowVersion = 0;
	private String rowProtection;

	/**
	 * Entity holding data of a approval data.
	 * 
	 * The constructor is responsible for populating all non-nullable fields!
	 */
	public ApprovalData(final int id, final ApprovalRequest approvalRequest) {
		setId(id);
		setApprovalid(approvalRequest.generateApprovalId());
		setApprovaltype(approvalRequest.getApprovalType());
		setEndentityprofileid(approvalRequest.getEndEntityProfileId());        
		setCaid(approvalRequest.getCAId());
		if(approvalRequest.getRequestAdminCert() != null){
			setReqadmincertissuerdn(CertTools.getIssuerDN(approvalRequest.getRequestAdminCert()));
			setReqadmincertsn(CertTools.getSerialNumberAsString(approvalRequest.getRequestAdminCert()));
		}
		setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);        
		setApprovals(new ArrayList<Approval>());
		setApprovalRequest(approvalRequest);                
		setRequestdate(System.currentTimeMillis());
		setExpiredate((new Date()).getTime() + approvalRequest.getRequestValidity());
		setRemainingapprovals(approvalRequest.getNumOfRequiredApprovals());
		log.debug("Created approval with id " + id);
	}

	public ApprovalData() { 
		// used from test code
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
	public int getApprovalid() { return approvalid; }
	/**
	 * Constructed from action data as actiontype, admin, username etc. It should
	 * result in the same approvalid if the admin tries to request the same action twice.
	 */
	public void setApprovalid(int approvalid) { this.approvalid = approvalid; } 

	/**   
	 * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
	 * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
	 */
	//@Column
	public int getApprovaltype() { return approvaltype; }
	/**
	 * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
	 * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
	 */
	public void setApprovaltype(int approvaltype) { this.approvaltype = approvaltype; }

	/**
	 * For RA specific approval requests should the related end entity profile id be specified
	 * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
	 */
	//@Column
	public int getEndentityprofileid() { return endentityprofileid; }
	/**
	 * For RA specific approval requests should the related end entity profile id be specified
	 * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
s	 */
	public void setEndentityprofileid(int endentityprofileid) { this.endentityprofileid = endentityprofileid; }

	/**
	 * For CA specific approval requests should the related ca id be specified
	 * for non ca request should this field be set to ApprovalDataVO.ANY_CA
	 */
	//@Column
	public int getCaid() { return caid; }
	/**
	 * For CA specific approval requests should the related ca id be specified
	 * for non ca request should this field be set to ApprovalDataVO.ANY_CA    
	 */
	public void setCaid(int caid) { this.caid = caid; }

	/**
	 * The issuerdn of the administrator certificate that generated the request.
	 */
	//@Column
	public String getReqadmincertissuerdn() { return reqadmincertissuerdn; }
	/**
	 * The issuerdn of the administrator certificate that generated the request.
	 */
	public void setReqadmincertissuerdn(String reqadmincertissuerdn) { this.reqadmincertissuerdn = reqadmincertissuerdn; }

	/**
	 * The serialnumber of the administrator certificate that generated the request. String in Hex.
	 */
	//@Column
	public String getReqadmincertsn() { return reqadmincertsn; }
	/**
	 * The serialnumber of the administrator certificate that generated the request. String in Hex.
	 */
	public void setReqadmincertsn(String reqadmincertsn) { this.reqadmincertsn = reqadmincertsn; }

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
	public String getApprovaldata() { return approvaldata; }

	/**
	 * Stringrepresentation of data of approvals made by one or more administrators
	 */
	public void setApprovaldata(String approvaldata) { this.approvaldata = approvaldata; }

	/**
	 * Data containing information about the request displayed for the approval administrator.
	 */
	//@Column @Lob
	public String getRequestdata() { return requestdata; }

	/**
	 * Data containing information about the request displayed for the approval administrator.
	 */
	public void setRequestdata(String requestdata) { this.requestdata = requestdata; }            

	/**
	 * Date the request for approval were added
	 */
	//@Column
	public long getRequestdate() { return requestdate; }
	/**
	 * Date the request for approval were added
	 */
	public void setRequestdate(long requestdate) { this.requestdate = requestdate; }

	/**
	 * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
	 * means that the request/approval never expires
	 */
	//@Column
	public long getExpiredate() { return expiredate; }
	/**
	 * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
	 * means that the request/approval never expires
	 */
	public void setExpiredate(long expiredate) { this.expiredate = expiredate; }

	/**
	 * Indicates the number of approvals that remains in order to execute the action
	 */
	//@Column
	public int getRemainingapprovals() { return remainingapprovals; }
	/**
	 * Indicates the number of approvals that remains in order to execute the action  
	 */
	public void setRemainingapprovals(int remainingapprovals) { this.remainingapprovals = remainingapprovals; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(final int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(final String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	public Collection<Approval> getApprovals() {   
		return ApprovalDataUtil.getApprovals(getApprovaldata());
	}

	/**
	 * Collection of Approval
	 * @param approvals cannot be null.
	 * @throws IOException
	 */
	private final void setApprovals(final Collection<Approval> approvals){
		try{
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final ObjectOutputStream oos = new ObjectOutputStream(baos);
			final int size = approvals.size();
			oos.writeInt(size);
			final Iterator<Approval> iter = approvals.iterator();
			while(iter.hasNext()){
				final Approval next = iter.next();
				oos.writeObject(next);
			}
			oos.flush();
			setApprovaldata(new String(Base64.encode(baos.toByteArray(),false)));
		} catch (IOException e) {
			log.error("Error building approvals.",e);
			throw new RuntimeException(e);
		}
	}

	@Transient
	public ApprovalRequest getApprovalRequest() {
		return ApprovalDataUtil.getApprovalRequest(requestdata);	//getRequestdata()
	}

	public final void setApprovalRequest(final ApprovalRequest approvalRequest){
		try{
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(approvalRequest);
			oos.flush();
			setRequestdata(new String(Base64.encode(baos.toByteArray(),false)));
		}catch(IOException e){
			log.error("Error building approval request.",e);
			throw new RuntimeException(e);   		
		}
	}

	@Transient
	private Date getRequestDate(){    
		return new Date(getRequestdate());
	}

	@Transient
	private Date getExpireDate(){    
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
	 * The status is set to expired of it as
	 * @return true of the request or approval have expired
	 */
	private boolean haveRequestOrApprovalExpired(){
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

    /**
     * Method that returns the approval data. This method currently extracts the ApprovalRequest object.
     */
	@Transient
    public String getRequestAdminUsername() {
    	return getApprovalRequest().getRequestAdmin().getUsername();
    }

	/**
	 * Method that returns the approval data.
	 */
	@Transient
	public ApprovalDataVO getApprovalDataVO() {
		haveRequestOrApprovalExpired();
		return new ApprovalDataVO(getId(), getApprovalid(),getApprovaltype(),
				getEndentityprofileid(),getCaid(),getReqadmincertissuerdn(),
				getReqadmincertsn(), getStatus(),getApprovals(), getApprovalRequest(),
				getRequestDate(),getExpireDate(),getRemainingapprovals());

	}

	/**
	 * Method adds an approval to the approval data.
	 * If the number of required approvals have been reached will
	 * the request be executed and expiredate set.
	 * 
	 * @throws ApprovalRequestExpiredException 
	 * @throws ApprovalRequestExecutionException 
	 * @throws ApprovalException 
	 */
	public void approve(final Approval approval) throws ApprovalRequestExpiredException, ApprovalRequestExecutionException, ApprovalException {
		if(haveRequestOrApprovalExpired()){
			throw new ApprovalRequestExpiredException();
		}
		if(getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			throw new ApprovalException("Wrong status of approval request.");
		}
		final int numberofapprovalsleft = getRemainingapprovals() -1;
		if(numberofapprovalsleft < 0){
			throw new ApprovalException("Error already enough approvals have been done on this request.");
		}
		setRemainingapprovals(numberofapprovalsleft);
		final Collection<Approval> approvals = getApprovals();
		approvals.add(approval);
		setApprovals(approvals);
		if(numberofapprovalsleft == 0){
			final ApprovalRequest approvalRequest = getApprovalRequest();
			if(approvalRequest.isExecutable()){
				try{
					approvalRequest.execute();
					setStatus(ApprovalDataVO.STATUS_EXECUTED);
				} catch(ApprovalRequestExecutionException e){
					setStatus(ApprovalDataVO.STATUS_EXECUTIONFAILED);
					throw e;
				}
				setStatus(ApprovalDataVO.STATUS_EXECUTED);
				setExpireDate(new Date());
			}else{
				setStatus(ApprovalDataVO.STATUS_APPROVED);
				setExpiredate((new Date()).getTime() + approvalRequest.getApprovalValidity());
			}
		}
	}

	/**
	 * Method that rejects an apporval.
	 * After someone have rejected the request noone else can approve it
	 * 
s	 * @throws ApprovalRequestExpiredException 
	 * @throws ApprovalRequestExecutionException 
	 * @throws ApprovalException 
	 */
	public void reject(final Approval approval) throws ApprovalRequestExpiredException,  ApprovalException {
		if(haveRequestOrApprovalExpired()){
			throw new ApprovalRequestExpiredException();
		}
		if(getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			throw new ApprovalException("Wrong status of approval request.");
		}
		final int numberofapprovalsleft = getRemainingapprovals() -1;
		if(numberofapprovalsleft < 0){
			throw new ApprovalException("Error already enough approvals have been done on this request.");
		}
		setRemainingapprovals(0);
		final Collection<Approval> approvals = getApprovals();
		approvals.add(approval);
		setApprovals(approvals);
		if(getApprovalRequest().isExecutable()){
			setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
			setExpireDate(new Date());    		    		
		}else{
			setStatus(ApprovalDataVO.STATUS_REJECTED);
			setExpiredate((new Date()).getTime() + getApprovalRequest().getApprovalValidity());   		
		}
	} 

	/**
	 * Method used by the requestadmin to check if an approval request have been approved
	 *
	 * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
	 * @throws ApprovalRequestExpiredException if the request or approval have expired, the status will be EXPIREDANDNOTIFIED in this case. 
	 */
	@Transient
	public int isApproved(final int step) throws ApprovalRequestExpiredException {    	
		if(getApprovalRequest().isStepDone(step)){
			return ApprovalDataVO.STATUS_EXPIRED;
		}
		if(haveRequestOrApprovalExpired()){
			if(getStatus() != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED &&
					getStatus() != ApprovalDataVO.STATUS_EXECUTED &&
					getStatus() != ApprovalDataVO.STATUS_EXECUTIONDENIED &&
					getStatus() != ApprovalDataVO.STATUS_EXECUTIONFAILED){
				setStatus(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED);
				throw new ApprovalRequestExpiredException();
			}
			return ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
		}
		if(getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			return getRemainingapprovals();
		}
		return getStatus();
	} 

	/**
	 * Method used to mark an non-executable approval as done
	 * if the last step is performed will the status be set as
	 * expired.
	 *
	 * @throws ApprovalRequestExpiredException if the step have already been executed
	 */
	public void markStepAsDone(final int step) throws ApprovalRequestExpiredException {
		final ApprovalRequest ar = getApprovalRequest();
		if (!ar.isExecutable() && getStatus() == ApprovalDataVO.STATUS_APPROVED) {
			if (!ar.isStepDone(step)) {
				ar.markStepAsDone(step);
				setApprovalRequest(ar);
				if (step == ar.getNumberOfApprovalSteps()-1) {
					setStatus(ApprovalDataVO.STATUS_EXPIRED);
				}
			} else {
				throw new ApprovalRequestExpiredException("Error step " + step + " of approval with id " + getApprovalid() + " have alread been performed");
			}
		}
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static ApprovalData findById(final EntityManager entityManager, final Integer id) {
		return entityManager.find(ApprovalData.class, id);
	}
	
	/** @return return the query results as a List. */
	public static List<ApprovalData> findByApprovalId(final EntityManager entityManager, final int approvalid) {
		final Query query = entityManager.createQuery("SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalid");
		query.setParameter("approvalid", approvalid);
		return query.getResultList();
	}
	
	/** @return return the query results as a List. */
	public static List<ApprovalData> findByApprovalIdNonExpired(final EntityManager entityManager, final int approvalid) {
		final Query query = entityManager.createQuery("SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalid AND (a.status>"+ApprovalDataVO.STATUS_EXPIRED+")");
		query.setParameter("approvalid", approvalid);
		return query.getResultList();
	}

	/** @return return the query results as a List<Integer>. */
	public static List<Integer> findByApprovalIdsByStatus(final EntityManager entityManager, final int status) {
		final Query query = entityManager.createQuery("SELECT a.approvalid FROM ApprovalData a WHERE a.status=:status");
		query.setParameter("status", status);
		return query.getResultList();
	}

	/** @return return the query results as a List<ApprovalData>. */
	public static List<ApprovalDataVO> findByCustomQuery(final EntityManager entityManager, final int index, final int numberofrows, final String customQuery) {
		final List<ApprovalDataVO> ret = new ArrayList<ApprovalDataVO>();
		// Hibernate on DB2 wont allow us to "SELECT *" in combination with setMaxResults.
		// Ingres wont let us access a LOB in a List using a native query for all fields.
		// -> So we will get a list of primary keys and the fetch the whole entities one by one...
		
		// As a sad little bonus on DB2, "SELECT id FROM ApprovalData WHERE "
		// is converted into "select * from ( select rownumber() over() as rownumber_, id FROM ApprovalData WHERE ... as temp_ where rownumber_ <= ?"
		final Query query = entityManager.createNativeQuery("SELECT id FROM ApprovalData WHERE " + customQuery);
		query.setFirstResult(index);
		query.setMaxResults(numberofrows);
		final List<Object> ids = query.getResultList();
		for (Object object : ids) {
			final int id = ValueExtractor.extractIntValue(object);
			ret.add(entityManager.find(ApprovalData.class, id).getApprovalDataVO());
		}
		return ret;
	}
}
