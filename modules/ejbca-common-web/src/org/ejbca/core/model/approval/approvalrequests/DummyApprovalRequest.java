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
package org.ejbca.core.model.approval.approvalrequests;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Dummy Approval Request used for testing and demonstration purposes. 
 * 
 * @version $Id$
 */
public class DummyApprovalRequest extends ApprovalRequest { 
	
	private static final long serialVersionUID = -2L;
	private static final Logger log = Logger.getLogger(DummyApprovalRequest.class);
	private static final int LATEST_VERSION = 1;
	
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
	public DummyApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int cAId, int endEntityProfileId, 
	            boolean executable, final ApprovalProfile approvalProfile) {
        super(requestAdmin, requestSignature, ApprovalRequest.REQUESTTYPE_SIMPLE, cAId, endEntityProfileId, approvalProfile);
		this.executable = executable;
	}  
	
    /**
     * Main constructor of an approval request with step functionality
     */
	public DummyApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int cAId, int endEntityProfileId, 
	        int steps, boolean executable, final ApprovalProfile approvalProfile) {
		super(requestAdmin, requestSignature, ApprovalRequest.REQUESTTYPE_SIMPLE, cAId, endEntityProfileId, 
		        steps, approvalProfile);	
		this.executable = executable;
	} 
	
    /** Constuctor used in externaliziation only */
    public DummyApprovalRequest() {
    }
    
	/**
	 * Should return true if the request if of the type that should be executed
	 * by the last approver.
	 * 
	 * False if the request admin should do a polling action to try again.
	 */
	public boolean isExecutable(){
		return executable;
	}
	
	/**
	 * A main function of the ApprovalRequest, the execute() method
	 * is run when all required approvals have been made.
	 * 
	 * execute should perform the action or nothing if the requesting admin
	 * is supposed to try his action again.
	 */
	@Override
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
		return (CertTools.getFingerprintAsString(getRequestAdminCert()) + getApprovalType() + getCAId() + 
		        getEndEntityProfileId() + getApprovalProfile().getProfileName()).hashCode(); 
	}

	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin){
		ArrayList<ApprovalDataText> newText = new ArrayList<ApprovalDataText>();
		newText.add(new ApprovalDataText("DUMMYDATAROW1: ", "YES" , false, false));
		newText.add(new ApprovalDataText("DUMMYDATAROW2: ", "YES" , false, false));
		return newText;
	}

	@Override
	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin){
		return null;
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
