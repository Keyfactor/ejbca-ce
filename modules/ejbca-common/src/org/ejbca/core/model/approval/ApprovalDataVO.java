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
package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

import org.ejbca.core.model.SecConst;

/**
 * Value Object containing all the information about an approval
 * such as approvalid, approvaltype, endentityprofileid, caid, 
 * reqadmincertissuerdn, reqadmincertsn, status, approvals (Collection),
 * requestdata, requestdate, expiredate, remainingapprovals
 * 
 * @version $Id$
 */
public class ApprovalDataVO implements Serializable { 	

	private static final long serialVersionUID = -1L;
	
	// Status constants
	public static final int STATUS_WAITINGFORAPPROVAL = -1;
	public static final int STATUS_APPROVED           = 0;
	public static final int STATUS_REJECTED           = -2;
	public static final int STATUS_EXPIRED            = -3;
	public static final int STATUS_EXPIREDANDNOTIFIED = -4; // Used to mark that the requester has been notified that the request has expired.
	public static final int STATUS_EXECUTED           = -5;
	public static final int STATUS_EXECUTIONFAILED    = -6;
	public static final int STATUS_EXECUTIONDENIED    = -7;

	// Approval types
	public static final int APPROVALTYPE_DUMMY                       = 0;
	public static final int APPROVALTYPE_VIEWHARDTOKENDATA           = 1;
	public static final int APPROVALTYPE_ADDENDENTITY                = 2;
	public static final int APPROVALTYPE_EDITENDENTITY               = 3;
	public static final int APPROVALTYPE_CHANGESTATUSENDENTITY       = 4;
	public static final int APPROVALTYPE_KEYRECOVERY                 = 5;
	public static final int APPROVALTYPE_GENERATETOKEN               = 6;
	public static final int APPROVALTYPE_REVOKEENDENTITY             = 7;
	public static final int APPROVALTYPE_REVOKEANDDELETEENDENTITY    = 8;
	public static final int APPROVALTYPE_REVOKECERTIFICATE           = 9;
	public static final int APPROVALTYPE_ACTIVATECATOKEN             = 10;
	
	//IMPORTANT REMEMBER TO SET THE RESOURCES IN BOTH INTERNAL AND ADMINWEB LANGUAGE FILES
	public static final String[] APPROVALTYPENAMES = {"APDUMMY","APVIEWHARDTOKENDATA","APADDENDENTITY","APEDITENDENTITY",
		                                              "APCHANGESTATUSENDENTITY", "APKEYRECOVERY", "APGENERATETOKEN",
		                                              "APREVOKEENDENTITY", "APREVOKEDELETEENDENTITY", "APREVOKECERTIFICATE",
                                                      "APPROVEACTIVATECA"};
	
	/** Used to indicate that the approval is applicable to any ca. */
	public static final int ANY_CA = SecConst.ALLCAS;
	
	/** Used to indicate that the approval is applicable to any end entity profile. */
	public static final int ANY_ENDENTITYPROFILE = SecConst.PROFILE_NO_PROFILE;

    private int id = 0;
    private int approvalId = 0;
    private int approvalType = 0;
    private int endEntityProfileiId = 0;
    private int cAId = 0;
    private String reqadmincertissuerdn = null;
    private String reqadmincertsn = null;
    private int status = 0;
    private Collection<Approval> approvals = null;
    private ApprovalRequest approvalRequest = null;
    private Date requestDate = null;
    private Date expireDate = null;
    private int remainingApprovals = 0;

	/**
	 * @param id unique row id
	 * @param approvalId    Constructed from action data as actiontype, admin, username etc. It should
     *                      result in the same approvalid if the admin tries to request the same action twice.
	 * @param approvalType  Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
     *                      constants ex: ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA
	 * @param endEntityProfileiId For RA specific approval requests should the related end entity profile id be specified
    *                       for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE
	 * @param cAId          For CA specific approval requests should the related ca id be specified
    *                       for non ca request should this field be set to ApprovalDataVO.ANY_CA
	 * @param reqadmincertissuerdn The issuerdn of the administrator certificate that generated the request.
	 * @param reqadmincertsn The serialnumber of the administrator certificate that generated the request. String in Hex
	 * @param status        Should be one of ApprovalDataVO.STATUS_ constants
	 * @param approvals     Collection of created Approvals (never null)
	 * @param approvalRequest The ApprovalRequest
	 * @param requestDate   Date the request for approval were added
	 * @param expireDate    Date the request for action or the approval action will expire, Long.MAX_VALUE 
     *                      means that the request/approval never expires
	 * @param remainingApprovals Indicates the number of approvals that remains in order to execute the action.
	 */
	public ApprovalDataVO(int id, int approvalId, int approvalType, int endEntityProfileiId, int cAId, String reqadmincertissuerdn, 
	        String reqadmincertsn, int status, Collection<Approval> approvals, ApprovalRequest approvalRequest, Date requestDate, 
	        Date expireDate, int remainingApprovals) {
		super();
		this.id = id;
		this.approvalId = approvalId;
		this.approvalType = approvalType;
		this.endEntityProfileiId = endEntityProfileiId;
		this.cAId = cAId;
		this.reqadmincertissuerdn = reqadmincertissuerdn;
		this.reqadmincertsn = reqadmincertsn;
		this.status = status;
		this.approvals = approvals;
		this.approvalRequest = approvalRequest;
		this.requestDate = requestDate;
		this.expireDate = expireDate;
		this.remainingApprovals = remainingApprovals;
	}
	/**
	 *  Constructed from action data as actiontype, admin, username etc. It should
     *  result in the same approvalid if the admin tries to request the same action twice.
	 * 
	 * @return Returns the approvalId.
	 */
	public int getApprovalId() {
		return approvalId;
	}
	/**
	 * The ApprovalRequest
	 * 
	 * @return Returns the approvalRequest.
	 */
	public ApprovalRequest getApprovalRequest() {
		return approvalRequest;
	}
	
	/**
	 * Collection of created Approvals (never null)
	 * 
	 * @return Returns the approvals.
	 */
	public Collection<Approval> getApprovals() {
		return approvals;
	}
	
	/**
	 * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
     * constants ex: ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA
	 * 
	 * @return Returns the approvalType.
	 */
	public int getApprovalType() {
		return approvalType;
	}
	
	/**
	 * For CA specific approval requests should the related ca id be specified
     * for non ca request should this field be set to ApprovalDataVO.ANY_CA
     *                       
	 * @return Returns the cAId.
	 */
	public int getCAId() {
		return cAId;
	}
	
	/**
	 *  For RA specific approval requests should the related end entity profile id be specified
     *  for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE
     *                       
	 * @return Returns the endEntityProfileiId.
	 */
	public int getEndEntityProfileiId() {
		return endEntityProfileiId;
	}
	
	/**
	 * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
     * means that the request/approval never expires
     * 
	 * @return Returns the expireDate.
	 */
	public Date getExpireDate() {
		return expireDate;
	}
	
	/**
	 * @return Returns the id.
	 */
	public int getId() {
		return id;
	}
	
	/**
	 * Indicates the number of approvals that remains in order to execute the action
	 * @return Returns the remainingApprovals.
	 */
	public int getRemainingApprovals() {
		return remainingApprovals;
	}
	
	/**
	 * The issuerdn of the administrator certificate that generated the request.
	 * 
	 * @return Returns the reqadmincertissuerdn.
	 */
	public String getReqadmincertissuerdn() {
		return reqadmincertissuerdn;
	}
	
	/**
	 * The serialnumber of the administrator certificate that generated the request. String in Hex
	 * 
	 * @return Returns the reqadmincertsn.
	 */
	public String getReqadmincertsn() {
		return reqadmincertsn;
	}
	
	/**
	 * Date the request for approval were added
	 * 
	 * @return Returns the requestDate.
	 */
	public Date getRequestDate() {
		return requestDate;
	}
	
	/**
	 * Should be one of ApprovalDataVO.STATUS_ constants
	 * 
	 * @return Returns the status.
	 */
	public int getStatus() {
		return status;
	}
}
