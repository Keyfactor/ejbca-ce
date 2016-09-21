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
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
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
import org.ejbca.core.model.approval.profile.ApprovalProfile;
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
            int cAId, int endEntityProfileId, final ApprovalProfile approvalProfile) {
    	super(requestAdmin, requestSignature, REQUESTTYPE_SIMPLE, cAId, endEntityProfileId, approvalProfile);
		this.userdata = userdata;
		this.clearpwd = clearpwd;
	}

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		throw new IllegalStateException("This execution requires additional bean references.");
	}
	
	public void execute(EndEntityManagementSession endEntityManagementSession, final int approvalRequestID, 
	        final AuthenticationToken lastApprovingAdmin) throws ApprovalRequestExecutionException {
		log.debug("Executing AddEndEntity for user:" + userdata.getUsername());
		
		// Add the ID of the approval request to the end entity as extended information.
        ExtendedInformation ext = userdata.getExtendedinformation();
        if(ext == null) {
            ext = new ExtendedInformation();
        }
        ext.setAddEndEntityApprovalRequestId(approvalRequestID);
        userdata.setExtendedinformation(ext);
		
		try{
			endEntityManagementSession.addUserAfterApproval(getRequestAdmin(), userdata, clearpwd, lastApprovingAdmin);
		} catch (EndEntityExistsException e) {
			throw new ApprovalRequestExecutionException("Error, user already exist", e);		
		} catch (AuthorizationDeniedException e) {
			throw new ApprovalRequestExecutionException("Authorization denied :" + e.getMessage(), e);
		} catch (UserDoesntFullfillEndEntityProfile e) {
			throw new ApprovalRequestExecutionException("User doesn't fullfil end entity profile:" + e.getMessage()  + e.getMessage(), e);			
		} catch (ApprovalException e) {
			throw new EJBException("This ApprovalException should never happen", e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This WaitingForApprovalException should never happen", e);
		} catch (CADoesntExistsException e) {
			throw new ApprovalRequestExecutionException("CA does not exist:" + e.getMessage(), e);
		} catch (EjbcaException e){
			throw new ApprovalRequestExecutionException("Failed adding user:" + e.getErrorCode() + e.getMessage(), e);
		} catch (PersistenceException e) {
		  throw new ApprovalRequestExecutionException("Database error", e);
		}
	}

    /**
     * Approval Id is generated for this approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
	@Override
	public int generateApprovalId() {
		if (log.isTraceEnabled()) {
		    log.trace(">generateApprovalId '"+getApprovalType() + ";" + userdata.getUsername() + ";" + getApprovalProfile().getProfileName()+"'");
		}
		return new String(getApprovalType() + ";" + userdata.getUsername() + ";" + getApprovalProfile().getProfileName()).hashCode();
	}

	@Override
	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_ADDENDENTITY;
	}
	
	public EndEntityInformation getEndEntityInformation() {
	    return userdata;
	}
	
	/** Returns a summary of the information in the request, without doing any database queries. See also the overloaded method */
	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
	    ArrayList<ApprovalDataText> retval = new ArrayList<>();
        retval.add(new ApprovalDataText("USERNAME",userdata.getUsername(),true,false));
        retval.add(new ApprovalDataText("SUBJECTDN",CertTools.stringToBCDNString(userdata.getDN()),true,false));
        retval.add(getTextWithNoValueString("SUBJECTALTNAME",userdata.getSubjectAltName()));
        String dirattrs = userdata.getExtendedinformation() != null ? userdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
        retval.add(getTextWithNoValueString("SUBJECTDIRATTRIBUTES",dirattrs));
        retval.add(getTextWithNoValueString("EMAIL",userdata.getEmail()));
        retval.add(new ApprovalDataText("KEYRECOVERABLE",userdata.getKeyRecoverable() ? "YES" : "NO",true,true));
        retval.add(new ApprovalDataText("SENDNOTIFICATION",userdata.getSendNotification() ? "YES" : "NO",true,true));       
        return retval;
	}
	
	public List<ApprovalDataText> getNewRequestDataAsText(CaSessionLocal caSession, EndEntityProfileSession endEntityProfileSession,
			CertificateProfileSession certificateProfileSession, HardTokenSession hardTokenSession) {
		ArrayList<ApprovalDataText> retval = new ArrayList<>();
		retval.add(new ApprovalDataText("USERNAME",userdata.getUsername(),true,false));
		retval.add(new ApprovalDataText("SUBJECTDN",CertTools.stringToBCDNString(userdata.getDN()),true,false));
		retval.add(getTextWithNoValueString("SUBJECTALTNAME",userdata.getSubjectAltName()));
		String dirattrs = userdata.getExtendedinformation() != null ? userdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
		retval.add(getTextWithNoValueString("SUBJECTDIRATTRIBUTES",dirattrs));
		retval.add(getTextWithNoValueString("EMAIL",userdata.getEmail()));
		String caname;
		try {
			caname = caSession.getCAInfoInternal(userdata.getCAId()).getName();
		} catch (CADoesntExistsException e) {
			caname = "NotExist";
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

	@Override
	public boolean isExecutable() {		
		return true;
	}
	
	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(userdata);
		out.writeBoolean(clearpwd);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		userdata = (EndEntityInformation) in.readObject();
    		clearpwd = in.readBoolean();
        }
	}

}
