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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * Approval Request created when an administrator wants
 * to recovery a end entities keyset
 * 
 * @version $Id$
 */
public class KeyRecoveryApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;
	private static final Logger log = Logger.getLogger(KeyRecoveryApprovalRequest.class);
	private static final int LATEST_VERSION = 1;
		
	private String username;
	private Certificate cert;

	private boolean recoverNewestCert = false; 

	/** Constructor used in externalization only */
	public KeyRecoveryApprovalRequest() {}

	public KeyRecoveryApprovalRequest(Certificate cert, String username, boolean recoverNewestCert, 
	        AuthenticationToken requestAdmin, String requestSignature, int numOfReqApprovals, int cAId, 
	        int endEntityProfileId, ApprovalProfile approvalProfile, ApprovalProfile secondApprovalProfile) {
		super(requestAdmin, requestSignature, REQUESTTYPE_SIMPLE,
				numOfReqApprovals, cAId, endEntityProfileId, approvalProfile, secondApprovalProfile);
		this.username = username;
		this.cert = cert;
		this.recoverNewestCert = recoverNewestCert;
	}

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		throw new RuntimeException("This execution requires additional bean references.");
	}

    public void execute(EndEntityManagementSession endEntityManagementSession) throws ApprovalRequestExecutionException {
        log.debug("Executing mark for recovery for user:" + username);
        try {
            if (recoverNewestCert) {
                endEntityManagementSession.prepareForKeyRecovery(getRequestAdmin(), username, getEndEntityProfileId(), null);
            } else {
                endEntityManagementSession.prepareForKeyRecovery(getRequestAdmin(), username, getEndEntityProfileId(), cert);
            }
        } catch (AuthorizationDeniedException e) {
            throw new ApprovalRequestExecutionException("Authorization Denied :" + e.getMessage(), e);
        } catch (ApprovalException e) {
            throw new EJBException("This should never happen", e);
        } catch (WaitingForApprovalException e) {
            throw new EJBException("This should never happen", e);
        }
    }

    /**
     * Approval Id is generated of This approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
	public int generateApprovalId() {		
		return new String(getApprovalType() + ";" + username).hashCode();
	}

	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_KEYRECOVERY;
	}

	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
		ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
		retval.add(new ApprovalDataText("USERNAME",username,true,false));
		retval.add(new ApprovalDataText("CERTSERIALNUMBER",CertTools.getSerialNumberAsString(cert),true,false));
		retval.add(new ApprovalDataText("SUBJECTDN",CertTools.getSubjectDN(cert).toString(),true,false));
		retval.add(new ApprovalDataText("ISSUERDN",CertTools.getIssuerDN(cert).toString(),true,false));
		return retval;
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
				cert = CertTools.getCertfromByteArray(Base64.decode(certString.getBytes("UTF8")), Certificate.class);
			} catch (CertificateException e) {
				log.debug("Error deserializing certificate", e);
				throw new IOException(e.getMessage());
			}	
        }
	}
}
