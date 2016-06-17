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

import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Approval Request created when trying to edit an end entity.
 * 
 * @version $Id$
 */
public class ChangeStatusEndEntityApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;
	private static final Logger log = Logger.getLogger(ChangeStatusEndEntityApprovalRequest.class);
	private static final int LATEST_VERSION = 1;

	private String username;
	private int oldstatus;
	private int newstatus;
	
	/** Constructor used in externalization only */
	public ChangeStatusEndEntityApprovalRequest() {}

    public ChangeStatusEndEntityApprovalRequest(String username, int oldstatus, int newstatus, AuthenticationToken requestAdmin,
            String requestSignature, int cAId, int endEntityProfileId, ApprovalProfile approvalProfile) {
		super(requestAdmin, requestSignature, REQUESTTYPE_COMPARING, cAId, endEntityProfileId, 
		        approvalProfile);
		this.username = username;
		this.oldstatus = oldstatus;
		this.newstatus = newstatus;
	}

	/** Overrides ApprovalRequest.isAllowedTransition()
	 * @see ApprovalRequest#isAllowedTransition()
	 */
	public boolean isAllowedTransition() {
		boolean ret = false;
		// Allow Keyrecovery transitions until keyrecovery approvals have been implemented.
		if(newstatus == EndEntityConstants.STATUS_KEYRECOVERY){
			return true;
		}
		if (oldstatus == EndEntityConstants.STATUS_GENERATED) {
			switch (newstatus) {
			case EndEntityConstants.STATUS_GENERATED:
				ret = true;
				break;
			default:
				break;
			}			
		}
		if (oldstatus == EndEntityConstants.STATUS_NEW) {
			switch (newstatus) {
			case EndEntityConstants.STATUS_NEW:
				ret = true;
				break;
			case EndEntityConstants.STATUS_INPROCESS:
				ret = true;
				break;
			case EndEntityConstants.STATUS_GENERATED:
				ret = true;
				break;
			case EndEntityConstants.STATUS_FAILED:
				ret = true;
				break;
			default:
				break;
			}			
		}
		if (oldstatus == EndEntityConstants.STATUS_FAILED) {
			switch (newstatus) {
			case EndEntityConstants.STATUS_FAILED:
				ret = true;
				break;
			case EndEntityConstants.STATUS_INPROCESS:
				ret = true;
				break;
			case EndEntityConstants.STATUS_GENERATED:
				ret = true;
				break;
			default:
				break;
			}			
		}
		if (oldstatus == EndEntityConstants.STATUS_INPROCESS) {
			switch (newstatus) {
			case EndEntityConstants.STATUS_INPROCESS:
				ret = true;
				break;
			case EndEntityConstants.STATUS_GENERATED:
				ret = true;
				break;
			case EndEntityConstants.STATUS_FAILED:
				ret = true;
				break;
			default:
				break;
			}			
		}
		if (oldstatus == EndEntityConstants.STATUS_KEYRECOVERY) {
			switch (newstatus) {
			case EndEntityConstants.STATUS_KEYRECOVERY:
				ret = true;
				break;
			case EndEntityConstants.STATUS_INPROCESS:
				ret = true;
				break;
			case EndEntityConstants.STATUS_GENERATED:
				ret = true;
				break;
			case EndEntityConstants.STATUS_FAILED:
				ret = true;
				break;
			default:
				break;
			}			
		}
		return ret;
	}

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		throw new RuntimeException("This execution requires additional bean references.");
	}
	
	public void execute(EndEntityManagementSession endEntityManagementSession) throws ApprovalRequestExecutionException {
		log.debug("Executing Change Status  for user:" + username);
		try{
			endEntityManagementSession.setUserStatus(getRequestAdmin(), username, newstatus);
		} catch (AuthorizationDeniedException e) {
			throw new ApprovalRequestExecutionException("Authorization Denied :" + e.getMessage(), e);
		} catch (FinderException e) {
			throw new ApprovalRequestExecutionException("User with username + " + username  + " doesn't exist.", e);
		} catch (ApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This should never happen",e);
		} 
	}

    /**
     * Approval Id is generated of This approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
	public int generateApprovalId() {		
		return new String(getApprovalType() + ";" + username + ";" + getApprovalProfile().getProfileName()).hashCode();
	}

	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_CHANGESTATUSENDENTITY;
	}

	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
		ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
		retval.add(new ApprovalDataText("USERNAME",username,true,false));
		retval.add(new ApprovalDataText("STATUS",EndEntityConstants.getTranslatableStatusText(newstatus),true,true));		
		return retval;
	}
	
	@Override
	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin) {
		ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
		retval.add(new ApprovalDataText("USERNAME",username,true,false));
		retval.add(new ApprovalDataText("STATUS",EndEntityConstants.getTranslatableStatusText(oldstatus),true,true));		
		return retval;
	}

	public boolean isExecutable() {		
		return true;
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(username);
		out.writeInt(newstatus);
		out.writeInt(oldstatus);		
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		username = (String) in.readObject();
    		newstatus = in.readInt();
    		oldstatus = in.readInt();    		
        }
	}
}
