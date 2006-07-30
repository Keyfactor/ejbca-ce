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
package org.ejbca.core.model.approval;

import java.io.ByteArrayInputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;



/**
 * Abstract Base class representing one approval request created when
 * an administrator performs an action that requires an approval.
 * 
 * 
 * Contains information like:
 * Admin that performs the request
 * Data necessary to display the request to the approver
 * Eventual data necessary to execute the request. 
 *  
 * 
 * 
 * @author Philip Vendil
 * @version $Id: ApprovalRequest.java,v 1.2 2006-07-30 18:19:02 herrvendil Exp $
 */

public abstract class ApprovalRequest implements  Externalizable { 
	
	private static final long serialVersionUID = -1L;
	
	private static final Logger log = Logger.getLogger(ApprovalRequest.class);
	
	private static final int LATEST_VERSION = 1;
	
	/**
	 * Simple request type means that the approver will only see new data about the
	 * action and will not compare it to old data
	 */
	public static final int REQUESTTYPE_SIMPLE    = 1;
	
	/**
	 * Comparing request type means that the approving administrator have to
	 * compare old data with new data in the request.
	 * 
	 */
	public static final int REQUESTTYPE_COMPARING = 2;

    private String requestAdminCert = null; // Base64 encoding of x509certificate
    
    private String requestSignature = null;
    
    private int approvalRequestType = REQUESTTYPE_SIMPLE;
    
    private int numOfRequiredApprovals = 0;
    
    private int cAId = 0;
    
    private int endEntityProfileId = 0;
   
    /**
     * Main constructor of an approval request
     * @param requestAdminCert the certificate of the requesting admin
     * @param requestSignature signature of the requestor (OPTIONAL, for future use)
     * @param approvalRequestType one of TYPE_ constants
     * @param numOfRequiredApprovals 
     * @param cAId the related cAId of the request that the approver must be authorized to or ApprovalDataVO.ANY_CA in applicable to any ca
     * @param endEntityProfileId the related profile id that the approver must be authorized to or ApprovalDataVO.ANY_ENDENTITYPROFILE if applicable to any end entity profile
     */
	protected ApprovalRequest(X509Certificate requestAdminCert, String requestSignature, 
			                  int approvalRequestType, int numOfRequiredApprovals, int cAId, int endEntityProfileId) {
		super();
		
   	    setRequestAdminCert(requestAdminCert);
		this.requestSignature = requestSignature;
		this.approvalRequestType = approvalRequestType;
		this.numOfRequiredApprovals = numOfRequiredApprovals;
		this.cAId = cAId;
		this.endEntityProfileId = endEntityProfileId;
	}
	
	/**
	 * Constuctor used in externaliziation only
	 */
	public ApprovalRequest(){
	}
	
	/**
	 * Should return true if the request if of the type that should be executed
	 * by the last approver.
	 * 
	 * False if the request admin should do a polling action to try again.
	 */
	public abstract boolean isExecutable();
	
	/**
	 * A main function of the ApprovalRequest, the execute() method
	 * is run when all required approvals have been made.
	 * 
	 * execute should perform the action or nothing if the requesting admin
	 * is supposed to try his action again.
	 */
	public abstract void execute() throws ApprovalRequestExecutionException;
	
	/**
	 * Method that should generate an approval id for this type of
	 * approval, the same request i.e the same admin want's to do the
	 * same thing twice should result in the same approvalId.
	 */
	public abstract int generateApprovalId();
	
	/**
	 * This method should return the request data in text representation.
	 * This text is presented for the approving administrator in order
	 * for him to make a desition about the request.
	 * Use '\n' as line delimiter.
	 */
	public abstract String getNewRequestDataAsText();
	
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
	public abstract String getOldRequestDataAsText();
	

	/**
	 * Should return the time in second that the request should be valid
	 * or Long.MAX_VALUE if it should never expire
	 */
	public abstract long getRequestValidity();
	
	/**
	 * Should return the time in second that the approval should be valid
	 * or Long.MAX_VALUE if it should never expire
	 */
	public abstract long getApprovalValidity();
	
	
	/**
	 * Should return one of the ApprovalDataVO.APPROVALTYPE_ constants
	 */
	public abstract int getApprovalType();
	
	

    /**
     * Method returning the number of required approvals in order to execute the request.
     */
	public int getNumOfRequiredApprovals(){
		return numOfRequiredApprovals;
	}


	/**
	 * The type of requesttype, one of TYPE_ constants
	 * 
	 */
	public int getApprovalRequestType() {
		return approvalRequestType;
	}

	/**
	 * @return Returns the requestSignature. OPTIONAL
	 */
	public String getRequestSignature() {
		return requestSignature;
	}

    /**
     * Returns the related ca id.
     * The approving administrator must be authorized to this ca
     * in order to approve it.
     */
	public int getCAId() {
		return cAId;
	}
	
    /**
     * Returns the related end entity profile id.
     * The approving administrator must be authorized to this profile
     * in order to approve it.
     */
	public int getEndEntityProfileId() {
		return endEntityProfileId;
	}


	private void setRequestAdminCert(X509Certificate requestAdminCert) {				
		try {
			byte[] certbuf = requestAdminCert.getEncoded();
			this.requestAdminCert = new String(Base64.encode(certbuf));	
		} catch (CertificateEncodingException e) {
			log.error(e);
		}					
	}
	
	/**
	 * Returns the certificate of the request admin.
	 */
	public X509Certificate getRequestAdminCert() {			
      byte[] certbuf = Base64.decode(requestAdminCert.getBytes());
      CertificateFactory cf = CertTools.getCertificateFactory();
      X509Certificate x509cert = null;
      try {
    	  x509cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(certbuf));
      } catch (CertificateException e) {
    	  log.error(e);
      }
      return x509cert;
	}

	private transient Admin requestAdmin = null;
	protected Admin getRequestAdmin() {
		if(requestAdmin == null){
			requestAdmin = new Admin(getRequestAdminCert());
		}
		
		return requestAdmin;
	}
	

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(LATEST_VERSION);
		out.writeObject(this.requestAdminCert);
		out.writeObject(this.requestSignature);
		out.writeInt(this.approvalRequestType);
		out.writeInt(this.numOfRequiredApprovals);
		out.writeInt(this.cAId);
		out.writeInt(this.endEntityProfileId);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        
		int version = in.readInt();
		if(version == 1){
			this.requestAdminCert = (String) in.readObject();
			this.requestSignature = (String) in.readObject();
			this.approvalRequestType = in.readInt();
			this.numOfRequiredApprovals =  in.readInt();
			this.cAId = in.readInt();
			this.endEntityProfileId = in.readInt();
		}
		
	}


}
