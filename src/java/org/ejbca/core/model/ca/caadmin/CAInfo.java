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
 
package org.ejbca.core.model.ca.caadmin;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

import org.ejbca.core.model.ca.catoken.CATokenInfo;

/**
 * Holds nonsensitive information about a CA.
 *
 * @version $Id: CAInfo.java,v 1.14 2008-04-09 21:54:19 anatom Exp $
 */
public class CAInfo implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final int CATYPE_X509 = 1;  
    
    /** 
     * Constants indicating that the CA is selfsigned.
     */  
    public static final int SELFSIGNED = 1;
    /**
     * Constant indicating that the CA is signed by an external CA.
     */
    public static final int SIGNEDBYEXTERNALCA = 2;    
    
    /**
     * Constant indicating where the special caid border is. All CAs with CA id not below this value
     * should be created
     */
    public static final int SPECIALCAIDBORDER = 10;    
    
    
    /**
     * Constants indicating approvalsettings for this CA
     */
    public static final int REQ_APPROVAL_ADDEDITENDENTITY = 1;
    
    /**
     * Constants indicating approvalsettings for key recover this CA
     */
    public static final int REQ_APPROVAL_KEYRECOVER = 2;
    
    /**
     * Constants indicating approvalsettings for revocations this CA
     */
    public static final int REQ_APPROVAL_REVOCATION = 3;
    
    /**
     * Constants indicating approval settings for activation of CA tokens
     */
    public static final int REQ_APPROVAL_ACTIVATECATOKEN = 4;
        
    public static final int[] AVAILABLE_APPROVALSETTINGS={REQ_APPROVAL_ADDEDITENDENTITY, REQ_APPROVAL_KEYRECOVER, REQ_APPROVAL_REVOCATION, REQ_APPROVAL_ACTIVATECATOKEN};
    public static final String[] AVAILABLE_APPROVALSETTINGS_TEXTS={"APPROVEADDEDITENDENTITY","APPROVEKEYRECOVER", "APPROVEREVOCATION", "APACTIVATECATOKEN"};
    
    protected String subjectdn;
    protected int caid;
    protected String name;
    protected int status;
    protected int validity;
    protected Date expiretime;
    protected Date updatetime;
    protected int catype;
    protected int signedby;
    protected Collection certificatechain;
    protected CATokenInfo catokeninfo;
    protected String description;
    protected int revokationreason;
    protected Date revokationdate;
    protected int certificateprofileid;
    /** Default value 24 hours */
    protected int crlperiod = 24;
    /** Default value 0 */
    protected int crlIssueInterval = 0;
    /** Default value 10 minutes */
    protected int crlOverlapTime = 10;
    /** Default value 0 = disabled */
    protected int deltacrlperiod = 0; 
    protected Collection crlpublishers;  
	protected boolean finishuser;  
	protected Collection extendedcaserviceinfos;
	protected Collection approvalSettings;
	protected int numOfReqApprovals;
	protected boolean includeInHealthCheck;
    
    public CAInfo(){}
    
    public String getSubjectDN() {return subjectdn;}
    public int getCAId(){return this.caid;}
    public String getName() {return this.name;}
    public int getStatus() {return status;}
    public int getCAType() {return catype;}
    public int getSignedBy() {return signedby;}
    
    public int getValidity() { return validity;}
    public void setValidity(int validity) { this.validity = validity; }
    
    public Date getExpireTime() {return this.expiretime;}
    public Date getUpdateTime() {return this.updatetime;}

      
    /** Retrieves the certificate chain for the CA. The returned certificate chain MUST have the
	 * RootCA certificate in the last position and the CAs certificate in the first.
     */
    public Collection getCertificateChain(){ return certificatechain;}
    public CATokenInfo getCATokenInfo() {return this.catokeninfo;}
    
    public String getDescription(){ return this.description;}
    public void setDescription(String description){ this.description = description;}
    
    public int getRevokationReason(){ return this.revokationreason;}
    public Date getRevokationDate(){ return this.revokationdate;}    
    
    public void setCertificateProfileId(int _certificateprofileid) { this.certificateprofileid = _certificateprofileid; }
    public int getCertificateProfileId(){ return this.certificateprofileid; }
    
    public int getCRLPeriod(){ return crlperiod;}
    public void setCRLPeriod(int crlperiod){ this.crlperiod=crlperiod;}
    
    public int getDeltaCRLPeriod(){ return deltacrlperiod;}
    public void setDeltaCRLPeriod(int deltacrlperiod){ this.deltacrlperiod=deltacrlperiod;}
    
    public int getCRLIssueInterval(){ return crlIssueInterval;}
    public void setCRLIssueInterval(int crlissueinterval){ this.crlIssueInterval = crlissueinterval;}
  
    public int getCRLOverlapTime(){ return crlOverlapTime;}
    public void setCRLOverlapTime(int crloverlaptime){ this.crlOverlapTime = crloverlaptime;}

    public Collection getCRLPublishers(){ return crlpublishers;}
    public void setCRLPublishers(Collection crlpublishers){this.crlpublishers=crlpublishers;}    
    	
	public boolean getFinishUser(){ return finishuser;}
	public void setFinishUser(boolean finishuser){ this.finishuser=finishuser;}
	
	public boolean getIncludeInHealthCheck() {return this.includeInHealthCheck;}
	public void setincludeInHealthCheck(boolean includeInHealthCheck) {this.includeInHealthCheck = includeInHealthCheck;}
	
	/** Lists the extended CA services.
	 * 
	 * @return Collection of ExtendedCAServiceInfo
	 */
	public Collection getExtendedCAServiceInfos(){ return this.extendedcaserviceinfos;}
	public void setExtendedCAServiceInfos(Collection extendedcaserviceinfos){ this.extendedcaserviceinfos = extendedcaserviceinfos;}

	/**
	 * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
	 * action that requires approvals, default none 
	 * 
	 * Never null
	 */
	public Collection getApprovalSettings() {return approvalSettings;}
	/**
	 * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
	 * action that requires approvals
	 */
	public void setApprovalSettings(Collection approvalSettings) {this.approvalSettings = approvalSettings;}
	
	/**
	 * Returns true if the action requires approvals.
	 * @param action, on of the CAInfo.REQ_APPROVAL_ constants
	 */
	public boolean isApprovalRequired(int action){		
		return approvalSettings.contains(new Integer(action));
	}
	
	
	/**
	 * Returns the number of different administrators that needs to approve
	 * an action, default 1.
	 */
	public int getNumOfReqApprovals() {return numOfReqApprovals;}
	/**
	 * The number of different administrators that needs to approve
	 */
	public void setNumOfReqApprovals(int numOfReqApprovals) {this.numOfReqApprovals = numOfReqApprovals;}     	
	
}