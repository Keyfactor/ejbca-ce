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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;

/**
 * Representation of approval request data used to control request and their approvals.
 * 
 * @version $Id$
 */
@Entity
@Table(name="ApprovalData")
public class ApprovalData extends ProtectedData implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ApprovalData.class);

	private int id; // the unique id stored in the database, also referred to as requestID
	private int approvalId; // a hash of the request, referred to as approvalID
	private int approvalType;
	private int endEntityProfileId;
	private int cAId;
	private String reqAdminCertIssuerDn;
	private String reqAdminCertSn;
	private int status;
	private String approvalData; // list of approvals 
	private String requestData;
	private long requestDate;
	private long expireDate;
	private String email;
	private String subjectDn;	
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
		log.debug("Created approval with ID " + id);
	}

	public ApprovalData() { 
		// used from test code (also required by JPA!)
	}

	/** unique row id */
	//@Id @Column
	public int getId() { return id; }

	/** unique row id */
	public void setId(final int id) { this.id = id; }

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
	 * For RA specific approval requests should the related end entity profile id be specified
	 * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
	 */
	//@Column
	public int getEndEntityProfileId() { return endEntityProfileId; }
	/**
	 * For RA specific approval requests should the related end entity profile id be specified
	 * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
	 */
	public void setEndEntityProfileId(int endEntityProfileId) { this.endEntityProfileId = endEntityProfileId; }

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
	 * String representation of data of approvals made by one or more administrators
	 */
	//@Column @Lob
	public String getApprovaldata() { return approvalData; }

	/**
	 * String representation of data of approvals made by one or more administrators
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
     * SujectDn included in user credentials
     * @return subjectDn
     */
    public String getSubjectDn() { return subjectDn; }

    /**
     * Method used to set the subjectDn which included in the user credentials
     */
    public void setSubjectDn(String subjectDn) { this.subjectDn = subjectDn; }
    
    /**
     * Email included in user Credentials
     * @return email
     */
    public String getEmail() { return email; }

    /**
     * Method used to set the email which included in the user credentials
     */
    public void setEmail(String email) { this.email = email; }

	/**
	 * Indicates the number of approvals that remains in order to execute the action
	 * @deprecated in 6.6.0, the type of approval handled is now part of the approval profile
	 */
	//@Column
	@Deprecated
	public int getRemainingapprovals() {
	    // TODO remove this method when support for Ejbca 6.5.x is dropped
	    return remainingApprovals; 
	}
	/**
	 * Indicates the number of approvals that remains in order to execute the action  
	 */
	@Deprecated
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
        build.append(getId()).append(getApprovalid()).append(getApprovaltype()).append(getEndEntityProfileId()).append(getCaid()).append(getReqadmincertissuerdn());
        build.append(getReqadmincertsn()).append(getStatus()).append(getApprovaldata()).append(getRequestdata()).append(getRequestdate()).append(getExpiredate()).append(getRemainingapprovals());
        if (version >= 3) {
            build.append(getSubjectDn());
            build.append(getEmail());
        }
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 3;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
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
    
    /**
     * @return a value object representation of this entity bean
     */
    @Transient
    public ApprovalDataVO getApprovalDataVO() {
        hasRequestOrApprovalExpired();
        ApprovalDataVO result = new ApprovalDataVO(getId(), getApprovalid(), getApprovaltype(), getEndEntityProfileId(), getCaid(), getReqadmincertissuerdn(),
                getReqadmincertsn(), getStatus(), getApprovals(), getApprovalRequest(), getRequestDate(), getExpireDate());
        return result;
    }
    
    @Transient
    public ApprovalRequest getApprovalRequest() {
        ApprovalRequest retval = null;      
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(getRequestdata().getBytes())));
            retval= (ApprovalRequest) ois.readObject();
        } catch (IOException e) {
            log.error("Error building approval request.",e);
            throw new IllegalStateException(e);
        } catch (ClassNotFoundException e) {
            log.error("Error building approval request.",e);
            throw new IllegalStateException(e);
        }
        return retval;
    }
    
    @Transient
    public List<Approval> getApprovals() {
        List<Approval> retval = new ArrayList<>();
        try{
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(getApprovaldata().getBytes())));
            int size = ois.readInt();
            for(int i=0;i<size;i++){
                Approval next = (Approval) ois.readObject();
                retval.add(next);
            }
        } catch (IOException e) {
            log.error("Error building approvals.",e);
            throw new IllegalStateException(e);
        } catch (ClassNotFoundException e) {
            log.error("Error building approvals.",e);
            throw new IllegalStateException(e);
        }
        return retval;
    }
}
