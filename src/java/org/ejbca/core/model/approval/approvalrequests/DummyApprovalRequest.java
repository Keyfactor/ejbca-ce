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
package org.ejbca.core.model.approval.approvalrequests;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.security.cert.X509Certificate;


import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.util.CertTools;

/**
 * Dummy Approval Request used for testing and demonstration purposes. 
 *  
 * 
 * 
 * @author Philip Vendil
 * @version $Id: DummyApprovalRequest.java,v 1.1 2006-07-30 18:19:03 herrvendil Exp $
 */

public class DummyApprovalRequest extends ApprovalRequest { 
	
	private static final long serialVersionUID = -1L;

	private static final Logger log = Logger.getLogger(DummyApprovalRequest.class);
	
	private static final int LATEST_VERSION = 1;
	
	private static final int NUM_OF_REQUIRED_APPROVALS = 2;
	

   
	private boolean executable = false;
	
    /**
     * Main constructor of an approval request
     * @param requestAdminCert the certificate of the requesting admin
     * @param requestSignature signature of the requestor (OPTIONAL, for future use)
     * @param approvalRequestType one of TYPE_ constants
     * @param numOfRequiredApprovals 
     * @param cAId the related cAId of the request that the approver must be authorized to or ApprovalDataVO.ANY_CA in applicable to any ca
     * @param endEntityProfileId the related profile id that the approver must be authorized to or ApprovalDataVO.ANY_ENDENTITYPROFILE if applicable to any end entity profile
     */

	public DummyApprovalRequest(X509Certificate requestAdminCert, String requestSignature, int cAId, int endEntityProfileId, boolean executable) {
		super(requestAdminCert, requestSignature, ApprovalRequest.REQUESTTYPE_SIMPLE,
				NUM_OF_REQUIRED_APPROVALS, cAId, endEntityProfileId);	
		this.executable = executable;
		
	}  
	
	/**
	 * Constuctor used in externaliziation only
	 */
	public DummyApprovalRequest(){
	}
    
	/**
	 * Should return true if the request if of the type that should be executed
	 * by the last approver.
	 * 
	 * False if the request admin should do a polling action to try again.
	 */
	public  boolean isExecutable(){
		return executable;
	}
	
	/**
	 * A main function of the ApprovalRequest, the execute() method
	 * is run when all required approvals have been made.
	 * 
	 * execute should perform the action or nothing if the requesting admin
	 * is supposed to try his action again.
	 */
	public void execute() throws ApprovalRequestExecutionException{
		if(executable){
			log.info("Dummy Is Executable, this should be shown in the log");
		}else{
			log.error("Error: This shouldn't be logged, DummyApprovalRequest isn't executable");
		}
		
	}
	
	/**
	 * Method that should generate an approval id for this type of
	 * approval, the same request i.e the same admin want's to do the
	 * same thing twice should result in the same approvalId.
	 */
	public  int generateApprovalId(){
		return (CertTools.getFingerprintAsString(getRequestAdminCert()) + getApprovalType() + getCAId() + getEndEntityProfileId()).hashCode(); 
	}
	
	/**
	 * This method should return the request data in text representation.
	 * This text is presented for the approving administrator in order
	 * for him to make a desition about the request.
	 * Use '\n' as line delimiter.
	 */
	public String getNewRequestDataAsText(){
		return "This is a dummy approval request, \n\n" +
		       "Approve or Reject";
		
	}
	
	/**
	 * This method should return the original request data in text representation.
	 * Should only be implemented by TYPE_COMPARING ApprovalRequests.
	 * TYPE_SIMPLE requests should return null;
	 * 
	 * This text is presented for the approving administrator for him to
	 * compare of what will be done.
	 * 
	 * Use '\n' as line delimiter.
	 */
	public String getOldRequestDataAsText(){
		return null;
	}


	/**
	 * Should return the time in second that the request should be valid
	 * or Long.MAX_VALUE if it should never expire
	 * 
	 * Returns 4 s (For testscripts only. usually 30 minutes or something)
	 */
	public long getRequestValidity(){
		return 4 * 1000;
	}
	
	/**
	 * Should return the time in second that the approval should be valid
	 * or Long.MAX_VALUE if it should never expire
	 * 
	 * Returns 4 s (For testscripts only. usually 30 minutes or something)
	 */
	public long getApprovalValidity(){
		return 4 * 1000;
	}
	
	
	/**
	 * Should return one of the ApprovalDataVO.APPROVALTYPE_ constants
	 */
	public int getApprovalType(){
		return ApprovalDataVO.APPROVALTYPE_DUMMY;
	}


	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeBoolean(executable);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
        	this.executable = in.readBoolean();
        }

	}


}
