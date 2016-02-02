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
import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestHelper;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;

/**
 * Approval Request created when trying to add an end entity.
 * 
 * @version $Id$
 */
public class AddEndEntityApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;
	private static final Logger log = Logger.getLogger(AddEndEntityApprovalRequest.class);
	private static final int LATEST_VERSION = 1;	
	
	private EndEntityInformation userdata;
	private boolean clearpwd;

	/** Constructor used in externalization only */
	public AddEndEntityApprovalRequest() {}

    public AddEndEntityApprovalRequest(EndEntityInformation userdata, boolean clearpwd, AuthenticationToken requestAdmin, String requestSignature,
            int numOfReqApprovals, int cAId, int endEntityProfileId) {
		super(requestAdmin, requestSignature, REQUESTTYPE_SIMPLE, numOfReqApprovals, cAId, endEntityProfileId);
		this.userdata = userdata;
		this.clearpwd = clearpwd;
	}

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		throw new RuntimeException("This execution requires additional bean references.");
	}
	
	public void execute(EndEntityManagementSession endEntityManagementSession) throws ApprovalRequestExecutionException {
		log.debug("Executing AddEndEntity for user:" + userdata.getUsername());
		try{
			endEntityManagementSession.addUser(getRequestAdmin(), userdata, clearpwd);
		} catch (EndEntityExistsException e) {
			throw new ApprovalRequestExecutionException("Error, user already exists ocurred", e);		
		} catch (AuthorizationDeniedException e) {
			throw new ApprovalRequestExecutionException("Authorization Denied :" + e.getMessage(), e);
		} catch (UserDoesntFullfillEndEntityProfile e) {
			throw new ApprovalRequestExecutionException("User Doesn't fullfil end entity profile :" + e.getMessage()  + e.getMessage(), e);			
		} catch (ApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (CADoesntExistsException e) {
			throw new ApprovalRequestExecutionException("CA does not exist :" + e.getMessage(), e);
		} catch (EjbcaException e){
			throw new ApprovalRequestExecutionException("Failed adding user :" + e.getErrorCode() + e.getMessage(), e);
		} catch (PersistenceException e) {
		  throw new ApprovalRequestExecutionException("Database error", e);
		}
	}

    /**
     * Approval Id is generated for this approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
	public int generateApprovalId() {		
		return new String(getApprovalType() + ";" + userdata.getUsername()).hashCode();
	}

	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_ADDENDENTITY;
	}

	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
		throw new RuntimeException("This getNewRequestDataAsText requires additional bean references.");
	}
	
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin, CaSession caSession, EndEntityProfileSession endEntityProfileSession,
			CertificateProfileSession certificateProfileSession, HardTokenSession hardTokenSession) {
		ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
		retval.add(new ApprovalDataText("USERNAME",userdata.getUsername(),true,false));
		retval.add(new ApprovalDataText("SUBJECTDN",CertTools.stringToBCDNString(userdata.getDN()),true,false));
		retval.add(getTextWithNoValueString("SUBJECTALTNAME",userdata.getSubjectAltName()));
		String dirattrs = userdata.getExtendedinformation() != null ? userdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
		retval.add(getTextWithNoValueString("SUBJECTDIRATTRIBUTES",dirattrs));
		retval.add(getTextWithNoValueString("EMAIL",userdata.getEmail()));
		String caname;
		try {
			caname = caSession.getCAInfo(admin,  userdata.getCAId()).getName();
		} catch (CADoesntExistsException e) {
			caname = "NotExist";
		} catch (AuthorizationDeniedException e) {
			caname = "AuthDenied";
		}
		retval.add(new ApprovalDataText("CA", caname, true, false));
		retval.add(new ApprovalDataText("ENDENTITYPROFILE", endEntityProfileSession.getEndEntityProfileName(userdata.getEndEntityProfileId()),true,false));		
		retval.add(new ApprovalDataText("CERTIFICATEPROFILE", certificateProfileSession.getCertificateProfileName(userdata.getCertificateProfileId()),true,false));
		retval.add(ApprovalRequestHelper.getTokenName(hardTokenSession, userdata.getTokenType()));
		retval.add(getTextWithNoValueString("HARDTOKENISSUERALIAS", hardTokenSession.getHardTokenIssuerAlias(userdata.getHardTokenIssuerId())));
		retval.add(new ApprovalDataText("KEYRECOVERABLE",userdata.getKeyRecoverable() ? "YES" : "NO",true,true));
		retval.add(new ApprovalDataText("SENDNOTIFICATION",userdata.getSendNotification() ? "YES" : "NO",true,true));		
		return retval;
	}
	
	private ApprovalDataText getTextWithNoValueString(String header, String data){
		if(data==null || data.equals("")){
			return new ApprovalDataText(header,"NOVALUE",true,true);
		}
		return new ApprovalDataText(header,data,true,false);
	}

	@Override
	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin) {
		return null;
	}

	public boolean isExecutable() {		
		return true;
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(userdata);
		out.writeBoolean(clearpwd);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		userdata = (EndEntityInformation) in.readObject();
    		clearpwd = in.readBoolean();
        }
	}
}
