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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;

/**
 * Approval Request created when an administrator wants
 * to view hard token data.
 * 
 * @version $Id$
 */
public class ViewHardTokenDataApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;
	//private static final Logger log = Logger.getLogger(ViewHardTokenDataApprovalRequest.class);
	private static final int LATEST_VERSION = 1;
		
	private String dn;
	private String username;
	private String tokensn;
	private boolean viewpuk;

	/** Constructor used in externalization only */
	public ViewHardTokenDataApprovalRequest() {}

	public ViewHardTokenDataApprovalRequest(String username, String userDN, String tokensn, boolean viewPUK, AuthenticationToken requestAdmin, String requestSignature, int numOfReqApprovals, int cAId, int endEntityProfileId) {
		super(requestAdmin, requestSignature, REQUESTTYPE_SIMPLE, numOfReqApprovals, cAId, endEntityProfileId);
		this.username = username;
		this.dn = userDN;
		this.tokensn = tokensn;
		this.viewpuk = viewPUK;
	}

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		// This is a non-executable approval
	}

    /**
     * Approval Id is generated of This approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
	public int generateApprovalId() {		
		return new String(getApprovalType() + ";" + username + ";" + tokensn +";"+ CertTools.getFingerprintAsString(getRequestAdminCert())).hashCode();
	}

	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA;
	}

	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
		ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
		retval.add(new ApprovalDataText("USERNAME",username,true,false));		
		retval.add(new ApprovalDataText("SUBJECTDN",dn,true,false));
		retval.add(new ApprovalDataText("HARDTOKENSN",tokensn,true,false));
		if(viewpuk){
			retval.add(new ApprovalDataText("VIEWPUKENDENTITYRULE","YES",true,true));		  
		}else{
			retval.add(new ApprovalDataText("VIEWPUKENDENTITYRULE","NO",true,true));
		}
		return retval;
	}
	
	@Override
	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin) {
		return null;
	}

	public boolean isExecutable() {		
		return false;
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(username);
		out.writeObject(dn);
		out.writeObject(tokensn);
		out.writeBoolean(viewpuk);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		username = (String) in.readObject();
            dn = (String) in.readObject();
            tokensn = (String) in.readObject();
            viewpuk = in.readBoolean();
        }
	}
}
