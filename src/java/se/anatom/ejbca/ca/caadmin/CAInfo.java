package se.anatom.ejbca.ca.caadmin;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

/**
 * Holds nonsensitive information about a CA.
 *
 * @version $Id: CAInfo.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
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
     * Constant indicating where the special caid border is. All CAs with CA id below this value
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
    protected int certificateprofileid;
    protected int crlperiod;
    protected Collection crlpublishers;    
    
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

      
    public Collection getCertificateChain(){ return certificatechain;}
    public CATokenInfo getCATokenInfo() {return this.catokeninfo;}
    
    public String getDescription(){ return this.description;}
    public void setDescription(String description){ this.description = description;}
    
    public int getRevokationReason(){ return this.revokationreason;}
    
    public int getCertificateProfileId(){ return this.certificateprofileid; };
    
    public int getCRLPeriod(){ return crlperiod;}
    public void setCRLPeriod(int crlperiod){ this.crlperiod=crlperiod;}
  
    public Collection getCRLPublishers(){ return crlpublishers;}
    public void setCRLPublishers(Collection crlpublishers){ this.crlpublishers=crlpublishers;}    
}
