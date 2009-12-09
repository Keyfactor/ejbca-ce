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

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.Date;

import org.ejbca.core.model.log.Admin;



/**
 * Class representing one approval of a request data. 
 * Includes information like:
 * Approval admin certificate
 * isApproved (rejected otherwise)
 * ApprovalDate
 * Comment
 *  
 * 
 * Approvals is sorted by dates.
 * 
 * @author Philip Vendil
 * @version $Id$
 */

public class Approval implements Comparable, Externalizable { 
	
	private static final long serialVersionUID = -1L;
	
	private static final int LATEST_VERSION = 2;

	private Admin admin = null;
    private String adminCertIssuerDN = null;
    private String adminCertSerialNumber = null;
    private boolean approved = false;
    private Date approvalDate = null;
    private String comment = null;
    private String approvalSignature = null; 
    
	/**
	 * @param approved
	 * @param apDate
	 * @param comment
	 */
	public Approval(String comment) {
		super();
		this.approvalDate = new Date();
		this.comment = comment;
	}
	
	/**
	 * Constructor used in externalization only
	 */
	public Approval(){}

	/**
	 * @return Returns the adminCertIssuerDN.
	 * @deprecated Use the information from the Admin object instead
	 */
	public String getAdminCertIssuerDN() {
		return adminCertIssuerDN;
	}
	
	/**
	 * @return Returns the adminCertSerialNumber.
	 * @deprecated Use the information from the Admin object instead
	 */
	public BigInteger getAdminCertSerialNumber() {
		if (adminCertSerialNumber == null) {
			return null;
		}
		return new BigInteger(adminCertSerialNumber,16);
	}
	
	
	/**
	 * @return Returns the approvalDate.
	 */
	public Date getApprovalDate() {
		return approvalDate;
	}
	
	
	/**
	 * @return Returns the approved.
	 */
	public boolean isApproved() {
		return approved;
	}
	
	
	/**
	 * @return Returns the comment.
	 */
	public String getComment() {
		return comment;
	}		
	
	/**
	 * @return the Admin that approved this Approval
	 */
	public Admin getAdmin() { return admin; }

	/**
	 * Used specify rejection or approval
	 * @param approved true for approved, flase for rejected
	 * @param admin is the Admin that approved or rejected the current Approval
	 */
	public void setApprovalAdmin(boolean approved, Admin admin) {
		this.approved = approved;
		this.admin = admin;
	}
	
    /**
     * Sort by approval date
     */
	public int compareTo(Object arg0) {				
		return approvalDate.compareTo(((Approval) arg0).approvalDate);
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(LATEST_VERSION);
		out.writeObject(this.admin);
		out.writeBoolean(this.approved);
		out.writeObject(this.approvalDate);
		out.writeObject(this.comment);	
		out.writeObject(this.approvalSignature);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		int version = in.readInt();
		if(version == 1){
			this.adminCertIssuerDN = (String) in.readObject();
			this.adminCertSerialNumber = (String) in.readObject();
			this.approved = in.readBoolean();
			this.approvalDate = (Date) in.readObject();
			this.comment = (String) in.readObject();
			this.approvalSignature = (String) in.readObject();
			//this.username = (String) in.readObject(); This information is now available through the Admin object
		} else if (version == 2) {
			this.admin = (Admin) in.readObject();
			this.approved = in.readBoolean();
			this.approvalDate = (Date) in.readObject();
			this.comment = (String) in.readObject();
			this.approvalSignature = (String) in.readObject();
		}
	}
}
