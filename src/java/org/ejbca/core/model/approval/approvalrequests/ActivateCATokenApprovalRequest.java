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
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.log.Admin;

/**
 * Approval Request created when trying to activate a CA Token.
 *  
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class ActivateCATokenApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;

	private static final Logger log = Logger.getLogger(ActivateCATokenApprovalRequest.class);
	
	private static final int LATEST_VERSION = 1;	

	private String cAName = null;
	private String authenticationCode = null;

	
	/**
	 * Constuctor used in externaliziation only
	 */
	public ActivateCATokenApprovalRequest() {}

	/**
	 * Construct an approval request for the activation of a CA Token
	 * @param certificateSerialNumber
	 * @param issuerDN
	 * @param username
	 * @param reason
	 * @param requestAdmin
	 * @param numOfReqApprovals
	 * @param cAId
	 * @param endEntityProfileId
	 */
	public ActivateCATokenApprovalRequest(String cAName, String authenticationCode,
			Admin requestAdmin, int numOfReqApprovals, int cAId, int endEntityProfileId) {
		super(requestAdmin, null, REQUESTTYPE_SIMPLE, numOfReqApprovals, cAId, endEntityProfileId);
		this.cAName = cAName;
		this.authenticationCode = authenticationCode;

 
	} // RevocationApprovalRequest



	/**
	 * A main function of the ApprovalRequest, the execute() method
	 * is run when all required approvals have been made.
	 * 
	 * execute should perform the action or nothing if the requesting admin
	 * is supposed to try this action again.
	 */
	public void execute() throws ApprovalRequestExecutionException {
		log.debug("Executing " + ApprovalDataVO.APPROVALTYPENAMES[getApprovalType()] + " (" + getApprovalType() + ").");

		try {
		    Context ctx = new javax.naming.InitialContext();
		    ICAAdminSessionHome caadminsessionhome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"),
		    		ICAAdminSessionHome.class);
			ICAAdminSessionRemote caadminsession = caadminsessionhome.create();
			
			// Use 'null' for GlobalConfiguration here since it's only used to extract approval information in the underlying code..
			caadminsession.activateCAToken(getRequestAdmin(), getCAId(), authenticationCode, null);
		} catch (CATokenAuthenticationFailedException e) {
			throw new ApprovalRequestExecutionException("CA Token Authentication Failed :" + e.getMessage(), e);
		} catch (AuthorizationDeniedException e) {
			throw new ApprovalRequestExecutionException("Authorization denied to activate CA Token :" + e.getMessage(), e);
		} catch (CATokenOfflineException e) {
			throw new ApprovalRequestExecutionException("CA Token still off-line :" + e.getMessage(), e);
		} catch (CreateException e) {
			throw new ApprovalRequestExecutionException("Error creating userdata session", e);
		} catch (NamingException e) {
			throw new EJBException(e);
		} catch (RemoteException e) {
			throw new EJBException(e);
		} catch (ApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This should never happen",e);
		} finally{
			authenticationCode = "";
		}
	
	} // execute

	/**
	 * Method that should generate an approval id for this type of
	 * approval, the same request i.e the same admin want's to do the
	 * same thing twice should result in the same approvalId.
	 */
	public int generateApprovalId() {
		String idString = getApprovalType() + ";" + cAName;
		return idString.hashCode();
	} // generateApprovalId


	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_ACTIVATECATOKEN;
	}

	/**
	 * This method should return the request data in text representation.
	 * This text is presented for the approving administrator in order
	 * for him to make a decision about the request.
	 * 
	 * Should return a List of ApprovalDataText, one for each row
	 */
	public List getNewRequestDataAsText(Admin admin) {
		ArrayList retval = new ArrayList();
		if ( cAName != null ) {
			retval.add(new ApprovalDataText("CANAME",cAName,true,false));
		}
		
		return retval;
	}
	
	/**
	 * This method should return the original request data in text representation.
	 * Should only be implemented by TYPE_COMPARING ApprovalRequests.
	 * TYPE_SIMPLE requests should return null;
	 * 
	 * This text is presented for the approving administrator for him to
	 * compare of what will be done.
	 * 
	 * Should return a Collection of ApprovalDataText, one for each row
	 */
	public List getOldRequestDataAsText(Admin admin) {
		return null;
	}

	/**
	 * Should return true if the request if of the type that should be executed
	 * by the last approver.
	 * 
	 * False if the request admin should do a polling action to try again.
	 */
	public boolean isExecutable() {		
		return true;
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(cAName);
		out.writeObject(authenticationCode);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		cAName = (String) in.readObject();
    		authenticationCode = (String) in.readObject(); 		
        }

	}
}
