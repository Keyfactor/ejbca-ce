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
 * @version $Id: CAInfo.java,v 1.3 2006-05-26 17:23:28 anatom Exp $
 */
public abstract class CAInfo implements Serializable {

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
    
    protected String subjectdn;
    protected int caid;
    protected String name;
    protected int status;
    protected int validity;
    protected Date expiretime;
    protected int catype;
    protected int signedby;
    protected Collection certificatechain;
    protected CATokenInfo catokeninfo;
    protected String description;
    protected int revokationreason;
    protected Date revokationdate;
    protected int certificateprofileid;
    protected int crlperiod;
    protected int crlIssueInterval = 0;
    protected int crlOverlapTime = 10;
    protected Collection crlpublishers;  
	protected boolean finishuser;  
	protected Collection extendedcaserviceinfos;
    
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

      
    /** Retrieves the certificate chain for the CA. The returned certificate chain MUST have the
	 * RootCA certificate in the last position and the CAs certificate in the first.
     */
    public Collection getCertificateChain(){ return certificatechain;}
    public CATokenInfo getCATokenInfo() {return this.catokeninfo;}
    
    public String getDescription(){ return this.description;}
    public void setDescription(String description){ this.description = description;}
    
    public int getRevokationReason(){ return this.revokationreason;}
    public Date getRevokationDate(){ return this.revokationdate;}    
    
    public int getCertificateProfileId(){ return this.certificateprofileid; }
    
    public int getCRLPeriod(){ return crlperiod;}
    public void setCRLPeriod(int crlperiod){ this.crlperiod=crlperiod;}
    
    public int getCRLIssueInterval(){ return crlIssueInterval;}
    public void setCRLIssueInterval(int crlissueinterval){ this.crlIssueInterval = crlissueinterval;}
  
    public int getCRLOverlapTime(){ return crlOverlapTime;}
    public void setCRLOverlapTime(int crloverlaptime){ this.crlOverlapTime = crloverlaptime;}

    public Collection getCRLPublishers(){ return crlpublishers;}
    public void setCRLPublishers(Collection crlpublishers){this.crlpublishers=crlpublishers;}    
    	
	public boolean getFinishUser(){ return finishuser;}
	public void setFinishUser(boolean finishuser){ this.finishuser=finishuser;}
	
	public Collection getExtendedCAServiceInfos(){ return this.extendedcaserviceinfos;}
	public void setExtendedCAServiceInfos(Collection extendedcaserviceinfos){ this.extendedcaserviceinfos = extendedcaserviceinfos;}     	
	
}