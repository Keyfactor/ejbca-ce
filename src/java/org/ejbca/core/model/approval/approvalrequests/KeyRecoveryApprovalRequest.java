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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Approval Request created when an adminsitrator wants
 * to recovery a end entities keyset
 *  
 * 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class KeyRecoveryApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;

	private static final Logger log = Logger.getLogger(KeyRecoveryApprovalRequest.class);
	
	private static final int LATEST_VERSION = 1;
		
	private String username;
	private X509Certificate cert;
	
	
	private boolean recoverNewestCert = false; 
	
	
	
	/**
	 * Constuctor used in externaliziation only
	 */
	public KeyRecoveryApprovalRequest() {}


	public KeyRecoveryApprovalRequest(X509Certificate cert, String username, boolean recoverNewestCert, Admin requestAdmin, String requestSignature, int numOfReqApprovals, int cAId, int endEntityProfileId) {
		super(requestAdmin, requestSignature, REQUESTTYPE_SIMPLE,
				numOfReqApprovals, cAId, endEntityProfileId);
		this.username = username;
		this.cert = cert;
		this.recoverNewestCert = recoverNewestCert;
	}


	public void execute() throws ApprovalRequestExecutionException {
		log.debug("Executing mark for recovery for user:" + username);
		try{
		    Context ctx = new javax.naming.InitialContext();
		    IKeyRecoverySessionHome keyrechome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("KeyRecoverySession"), IKeyRecoverySessionHome.class);
		    IKeyRecoverySessionRemote keyrecsession = keyrechome.create();
			
			if(recoverNewestCert){
				keyrecsession.markNewestAsRecoverable(getRequestAdmin(), username, getEndEntityProfileId());
			}else{
				keyrecsession.markAsRecoverable(getRequestAdmin(), cert, getEndEntityProfileId());
			}
 
		    
		}catch (CreateException e) {
			throw new ApprovalRequestExecutionException("Error creating new userdata session", e);
		} catch (AuthorizationDeniedException e) {
			throw new ApprovalRequestExecutionException("Authorization Denied :" + e.getMessage(), e);
		} catch (ApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (NamingException e) {
			throw new EJBException(e);
		} catch (RemoteException e) {
			throw new EJBException(e);
		} 

	}

    /**
     * Approval Id is genereated of This approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
	public int generateApprovalId() {		
		return new String(getApprovalType() + ";" + username).hashCode();
	}


	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_KEYRECOVERY;
	}


	public List getNewRequestDataAsText(Admin admin) {
		ArrayList retval = new ArrayList();
		retval.add(new ApprovalDataText("USERNAME",username,true,false));
		retval.add(new ApprovalDataText("CERTSERIALNUMBER",cert.getSerialNumber().toString(16),true,false));
		retval.add(new ApprovalDataText("SUBJECTDN",cert.getSubjectDN().toString(),true,false));
		retval.add(new ApprovalDataText("ISSUERDN",cert.getIssuerDN().toString(),true,false));
		return retval;
	}
	
	public List getOldRequestDataAsText(Admin admin) {
		return null;
	}


	public boolean isExecutable() {		
		return true;
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(username);
		out.writeBoolean(recoverNewestCert);
		try {
			String certString = new String(Base64.encode(cert.getEncoded()),"UTF8");
			out.writeObject(certString);
		} catch (CertificateEncodingException e) {
			log.debug("Error serializing certificate", e);
			throw new IOException(e.getMessage());
		}	
		
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		username = (String) in.readObject();
    		recoverNewestCert = in.readBoolean();
    		String certString = (String) in.readObject();    		
    		try {
				cert = CertTools.getCertfromByteArray(Base64.decode(certString.getBytes("UTF8")));
			} catch (CertificateException e) {
				log.debug("Error deserializing certificate", e);
				throw new IOException(e.getMessage());
			}	
        }

	}

}
