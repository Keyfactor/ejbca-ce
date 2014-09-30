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
package org.ejbca.core.model.approval;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
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

//Suppress warnings for deprecation of the Admin object, required for legacy support
@SuppressWarnings("deprecation") 
public class Approval implements Comparable<Approval>, Externalizable { 
	
	private static final long serialVersionUID = -1L;
	
	private static final int LATEST_VERSION = 3;

	private AuthenticationToken admin = null;
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
	public AuthenticationToken getAdmin() { return admin; }

	/**
	 * Used specify rejection or approval
	 * @param approved true for approved, flase for rejected
	 * @param admin is the Admin that approved or rejected the current Approval
	 */
	public void setApprovalAdmin(boolean approved, AuthenticationToken admin) {
		this.approved = approved;
		this.admin = admin;
	}
	
    /**
     * Sort by approval date
     */
	public int compareTo(Approval arg0) {				
		return approvalDate.compareTo(arg0.approvalDate);
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
            final Admin admin = (Admin) in.readObject();
            final X509Certificate x509cert = (X509Certificate)admin.getAdminInformation().getX509Certificate();
            if (x509cert != null) {
                Set<X509Certificate> credentials = new HashSet<X509Certificate>();
                credentials.add(x509cert);
                Set<X500Principal> principals = new HashSet<X500Principal>();
                principals.add(x509cert.getSubjectX500Principal());
                this.admin = new X509CertificateAuthenticationToken(principals, credentials);            	
				this.adminCertIssuerDN = CertTools.getIssuerDN(x509cert);
				this.adminCertSerialNumber = CertTools.getSerialNumberAsString(x509cert);
            } else if ((admin.getAdminType() >= 0) && (admin.getAdminType() <= 5)) {
				// We trust this admin as if it were created internal to EJBCA and fill in the auth token
            	this.admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(admin.getUsername()));
            }
			this.approved = in.readBoolean();
			this.approvalDate = (Date) in.readObject();
			this.comment = (String) in.readObject();
			this.approvalSignature = (String) in.readObject();
		} else if (version == 3) {
			this.admin = (AuthenticationToken) in.readObject();
			if (this.admin instanceof AlwaysAllowLocalAuthenticationToken) {
				// We trust this admin as if it were created internal to EJBCA and fill in the auth token
				this.admin = new AlwaysAllowLocalAuthenticationToken(this.admin.getPrincipals().iterator().next());
			} else if (this.admin instanceof X509CertificateAuthenticationToken) {
				X509CertificateAuthenticationToken xtok = (X509CertificateAuthenticationToken)this.admin;
				this.adminCertIssuerDN = CertTools.getIssuerDN(xtok.getCertificate());
				this.adminCertSerialNumber = CertTools.getSerialNumberAsString(xtok.getCertificate());
			}
			this.approved = in.readBoolean();
			this.approvalDate = (Date) in.readObject();
			this.comment = (String) in.readObject();
			this.approvalSignature = (String) in.readObject();
		}
	}
}
