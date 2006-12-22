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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceRequest;
import org.ejbca.core.model.ca.catoken.CAToken;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.HardCATokenContainer;
import org.ejbca.core.model.ca.catoken.HardCATokenManager;
import org.ejbca.core.model.ca.catoken.NullCAToken;
import org.ejbca.core.model.ca.catoken.SoftCAToken;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;




/**
 * CA is a base class that should be inherited by all CA types
 *
 * @version $Id: CA.java,v 1.15 2006-12-22 13:31:30 herrvendil Exp $
 */
public abstract class CA extends UpgradeableDataHashMap implements Serializable {

    /** Log4j instance */
    private static Logger log = Logger.getLogger(CA.class);

	public static final String TRUE  = "true";
    public static final String FALSE = "false";
    
    // protected fields.
    public    static final String CATYPE                         = "catype";
    protected static final String SUBJECTDN                      = "subjectdn";
    protected static final String CAID                           = "caid";
    protected static final String NAME                           = "name";
    protected static final String STATUS                         = "status";
    protected static final String VALIDITY                       = "validity";
    protected static final String EXPIRETIME                     = "expiretime";
    protected static final String CERTIFICATECHAIN               = "certificatechain";
    protected static final String CATOKENDATA                    = "catoken";
    protected static final String SIGNEDBY                       = "signedby";
    protected static final String DESCRIPTION                    = "description";
    protected static final String REVOKATIONREASON               = "revokationreason";
	protected static final String REVOKATIONDATE                 = "revokationdate";
    protected static final String CERTIFICATEPROFILEID           = "certificateprofileid";
    protected static final String CRLPERIOD                      = "crlperiod";
    protected static final String CRLISSUEINTERVAL               = "crlIssueInterval";
    protected static final String CRLOVERLAPTIME                 = "crlOverlapTime";
    protected static final String CRLPUBLISHERS                  = "crlpublishers";
	protected static final String FINISHUSER                     = "finishuser";
	protected static final String REQUESTCERTCHAIN               = "requestcertchain";
	protected static final String EXTENDEDCASERVICES             = "extendedcaservices";
	protected static final String EXTENDEDCASERVICE              = "extendedcaservice";
	protected static final String APPROVALSETTINGS               = "approvalsettings";
	protected static final String NUMBEROFREQAPPROVALS           = "numberofreqapprovals";
    
    // Public Methods
    /** Creates a new instance of CA, this constuctor should be used when a new CA is created */
    public CA(CAInfo cainfo){
       data = new HashMap();
       
       this.cainfo = cainfo;
              
       data.put(VALIDITY, new Integer(cainfo.getValidity()));
       data.put(SIGNEDBY, new Integer(cainfo.getSignedBy()));
       data.put(DESCRIPTION, cainfo.getDescription());
       data.put(REVOKATIONREASON, new Integer(-1));
       data.put(CERTIFICATEPROFILEID, new Integer(cainfo.getCertificateProfileId()));
       setCRLPeriod(cainfo.getCRLPeriod());
       setCRLIssueInterval(cainfo.getCRLIssueInterval());
       setCRLOverlapTime(cainfo.getCRLOverlapTime());
       setCRLPublishers(cainfo.getCRLPublishers());
       setFinishUser(cainfo.getFinishUser());
       
	   
	   Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
	   ArrayList extendedservicetypes = new ArrayList(); 
	   while(iter.hasNext()){
	   	 ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();
	   	 if(next instanceof OCSPCAServiceInfo){
	   	   setExtendedCAService(new OCSPCAService(next));
	   	   extendedservicetypes.add(new Integer(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE));
	   	 }
	   	 if(next instanceof XKMSCAServiceInfo){
		   setExtendedCAService(new XKMSCAService(next));
		   extendedservicetypes.add(new Integer(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE));
		 }
	   }
	   data.put(EXTENDEDCASERVICES, extendedservicetypes);
	   setApprovalSettings(cainfo.getApprovalSettings());
	   setNumOfRequiredApprovals(cainfo.getNumOfReqApprovals());
    }
    
    /** Constructor used when retrieving existing CA from database. */
    public CA(HashMap data){
      loadData(data);
      extendedcaservicemap = new HashMap();
    }
    public void setCAInfo(CAInfo cainfo) {
        this.cainfo = cainfo;    	
    }
    public CAInfo getCAInfo() {
        return this.cainfo;    	
    }

    // Public Methods.
    public String getSubjectDN(){
    	return cainfo.getSubjectDN();
    }
    public void setSubjectDN(String subjectdn){
    	cainfo.subjectdn = subjectdn;
    }
    
    public int getCAId(){
    	return cainfo.getCAId();
    }    
    public void setCAId(int caid){
    	cainfo.caid = caid;
    }    
    
    public String getName(){
    	return cainfo.getName();
    }
    public void setName(String caname){
    	cainfo.name = caname;
    }
    
    public int getStatus(){
    	return cainfo.getStatus();	
    }
    public void setStatus(int status){
    	cainfo.status = status;	
    }
    
    public int getCAType(){ return ((Integer)data.get(CATYPE)).intValue();}
    
    public int getValidity(){ return ((Integer) data.get(VALIDITY)).intValue();}
    public void setValidity(int validity){ data.put(VALIDITY,  new Integer(validity));}
    
    public Date getExpireTime(){return ((Date)data.get(EXPIRETIME));}
    public void setExpireTime(Date expiretime) { data.put(EXPIRETIME,expiretime);}    
   
    public int getSignedBy(){ return ((Integer) data.get(SIGNEDBY)).intValue();}
    
    public String getDescription(){return ((String)data.get(DESCRIPTION));}
    public void setDescription(String description) { data.put(DESCRIPTION,description);}  
    
    public int getRevokationReason(){return ((Integer) data.get(REVOKATIONREASON)).intValue();}
    public void setRevokationReason(int reason){ data.put(REVOKATIONREASON,new Integer(reason));}
        
	public Date getRevokationDate(){return (Date) data.get(REVOKATIONDATE);}
	public void setRevokationDate(Date date){ data.put(REVOKATIONDATE,date);}
                
    public int  getCRLPeriod(){return ((Integer)data.get(CRLPERIOD)).intValue();}
    public void setCRLPeriod(int crlperiod) {data.put(CRLPERIOD, new Integer(crlperiod));}
    
    public int  getCRLIssueInterval(){return ((Integer)data.get(CRLISSUEINTERVAL)).intValue();}
    public void setCRLIssueInterval(int crlIssueInterval) {data.put(CRLISSUEINTERVAL, new Integer(crlIssueInterval));}
    
    public int  getCRLOverlapTime(){return ((Integer)data.get(CRLOVERLAPTIME)).intValue();}
    public void setCRLOverlapTime(int crlOverlapTime) {data.put(CRLOVERLAPTIME, new Integer(crlOverlapTime));}

    public Collection  getCRLPublishers(){return ((Collection)data.get(CRLPUBLISHERS));}
    public void setCRLPublishers(Collection crlpublishers) {data.put(CRLPUBLISHERS, crlpublishers);}    
    
    
    public int getCertificateProfileId() {return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();}
    
    /** Returns the CAs token. The token is fetched from the token registry, or created and added to the token registry.
     * 
     * @return The CAs token, be it soft or hard.
     * @throws IllegalKeyStoreException If the token keystore is invalid (crypto error thrown by crypto provider), or the CA token type is undefined.
     */
    public CAToken getCAToken(int caid) throws IllegalKeyStoreException {
        CAToken ret = HardCATokenManager.instance().getCAToken(caid);
        if (ret == null) {
        	Integer tokentype = (Integer) ((HashMap)data.get(CATOKENDATA)).get(CAToken.CATOKENTYPE);
            switch(tokentype.intValue()) {
            case CATokenInfo.CATOKENTYPE_P12:
                ret = new SoftCAToken((HashMap)data.get(CATOKENDATA));
                break;
            case CATokenInfo.CATOKENTYPE_HSM:
                ret = new HardCATokenContainer((HashMap)data.get(CATOKENDATA)); 
                break;
            case CATokenInfo.CATOKENTYPE_NULL:
                ret = new NullCAToken();
                break;
            default:
                throw new IllegalKeyStoreException("No CA Token type defined: "+tokentype.intValue());
            }
            HardCATokenManager.instance().addCAToken(caid, ret);
        }            
      return ret;    	
    }
    /** Returns the CAs token. The token is fetched from the token registry, or created and added to the token registry.
     * 
     * @return The CAs token, be it soft or hard.
     * @throws IllegalKeyStoreException If the token keystore is invalid (crypto error thrown by crypto provider), or the CA token type is undefined.
     */
    public CAToken getCAToken() throws IllegalKeyStoreException {
    	return getCAToken(getCAId());
    }    
        
    /** Sets the CA token. Adds or updates the token in the token registry.
     * 
     * @param catoken The CAs token, be it soft or hard.
     */
    public void setCAToken(CAToken catoken){
       data.put(CATOKENDATA, catoken.saveData());        
       HardCATokenManager.instance().addCAToken(getCAId(), catoken);
    }
    
    public Collection getRequestCertificateChain(){
      if(requestcertchain == null){
        Collection storechain = (Collection) data.get(REQUESTCERTCHAIN);
        Iterator iter = storechain.iterator();
        this.requestcertchain = new ArrayList();
        while(iter.hasNext()){
          String b64Cert = (String) iter.next();
          try{
            this.requestcertchain.add(CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes())));
          }catch(Exception e){
             throw new EJBException(e);   
          }
        }        
      }
        
      return requestcertchain; 
    }
    
    public void setRequestCertificateChain(Collection requestcertificatechain){
      Iterator iter = requestcertificatechain.iterator();
      ArrayList storechain = new ArrayList();
      while(iter.hasNext()){
        Certificate cert = (Certificate) iter.next();
        try{ 
          String b64Cert = new String(Base64.encode(cert.getEncoded()));
          storechain.add(b64Cert);
        }catch(Exception e){
          throw new EJBException(e);  
        }  
      }
      data.put(REQUESTCERTCHAIN,storechain);  
      
      this.requestcertchain = new ArrayList();
      this.requestcertchain.addAll(requestcertificatechain);
    }

    /* Returns a collection of CA-certificates, with this CAs cert i position 0, or null
     * if no CA-certificates exist.
     */
	public Collection getCertificateChain(){
	  if(certificatechain == null){
		Collection storechain = (Collection) data.get(CERTIFICATECHAIN);
		if (storechain == null) {
			return null;
		}
		Iterator iter = storechain.iterator();
		this.certificatechain = new ArrayList();
		while(iter.hasNext()){
		  String b64Cert = (String) iter.next();
		  try{
			this.certificatechain.add(CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes())));
		  }catch(Exception e){
			 throw new EJBException(e);   
		  }
		}        
	  }
	  return certificatechain; 
	}
    
	public void setCertificateChain(Collection certificatechain){
	  Iterator iter = certificatechain.iterator();
	  ArrayList storechain = new ArrayList();
	  while(iter.hasNext()){
		Certificate cert = (Certificate) iter.next();
		try{ 
		  String b64Cert = new String(Base64.encode(cert.getEncoded()));
		  storechain.add(b64Cert);
		}catch(Exception e){
		  throw new EJBException(e);  
		}  
	  }
	  data.put(CERTIFICATECHAIN,storechain);  
      
	  this.certificatechain = new ArrayList();
	  this.certificatechain.addAll(certificatechain);
	}

    
    /* Returns the CAs certificate, or null if no CA-certificates exist.
     */
    public Certificate getCACertificate(){       
       if(certificatechain == null) { 
    	   getCertificateChain();
    	   // if it's still null, return null
           if (certificatechain == null) {
        	   return null;
           }
       }
       return (Certificate) this.certificatechain.get(0);
    }
    
	public boolean  getFinishUser(){return ((Boolean)data.get(FINISHUSER)).booleanValue();}
	
	public void setFinishUser(boolean finishuser) {data.put(FINISHUSER, new Boolean(finishuser));}    
    
	/**
	 * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
	 * action that requires approvals, default none 
	 * 
	 * Never null
	 * @return
	 */
	public Collection getApprovalSettings(){
		if(data.get(APPROVALSETTINGS) == null){
			return new ArrayList();
		}
		
		return (Collection) data.get(APPROVALSETTINGS);
	}
	
	/**
	 * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
	 * action that requires approvals
	 */
	public  void setApprovalSettings(Collection approvalSettings){
       data.put(APPROVALSETTINGS,approvalSettings);
	}
	
	/**
	 * Returns the number of different administrators that needs to approve
	 * an action, default 1.
	 */
	public int getNumOfRequiredApprovals(){
		if(data.get(NUMBEROFREQAPPROVALS) == null){
			return 1;
		}		
		return ((Integer) data.get(NUMBEROFREQAPPROVALS)).intValue();
	}
	
	/**
	 * The number of different administrators that needs to approve
	 */
    public void setNumOfRequiredApprovals(int numOfReqApprovals){
    	data.put(NUMBEROFREQAPPROVALS,new Integer(numOfReqApprovals));
    }
	
    public void updateCA(CAInfo cainfo) throws Exception{            
    	data.put(VALIDITY, new Integer(cainfo.getValidity()));                 
    	data.put(DESCRIPTION, cainfo.getDescription());      
    	data.put(CRLPERIOD, new Integer(cainfo.getCRLPeriod()));
    	data.put(CRLISSUEINTERVAL, new Integer(cainfo.getCRLIssueInterval()));
    	data.put(CRLOVERLAPTIME, new Integer(cainfo.getCRLOverlapTime()));
    	data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
    	data.put(APPROVALSETTINGS,cainfo.getApprovalSettings());
    	data.put(NUMBEROFREQAPPROVALS,new Integer(cainfo.getNumOfReqApprovals()));
    	CAToken token = getCAToken();
    	if (token != null) {
    		token.updateCATokenInfo(cainfo.getCATokenInfo());
    		setCAToken(token);
    	}
    	setFinishUser(cainfo.getFinishUser());
    	
    	Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
    	while(iter.hasNext()){
    		ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
    		if(info instanceof OCSPCAServiceInfo){
    			this.getExtendedCAService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE).update(info, this);	
    		}
    		if(info instanceof XKMSCAServiceInfo){
    			this.getExtendedCAService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE).update(info, this);	
    		}
    	}
    	this.cainfo = cainfo;
    }
    
    
    public Certificate generateCertificate(UserDataVO subject, 
            PublicKey publicKey, 
            int keyusage, 
            long validity,
            CertificateProfile certProfile) throws Exception {
    	// Calculate the notAfter date
    	Date notAfter = null;
        if(validity != -1) {
            notAfter = new Date();
            notAfter.setTime(notAfter.getTime() + ( validity * 24 * 60 * 60 * 1000));        	
        }
        Date notBefore = new Date(); 
    	return generateCertificate(subject, publicKey, keyusage, notBefore, notAfter, certProfile); 
    }
    
    public abstract Certificate generateCertificate(UserDataVO subject, 
                                                    PublicKey publicKey, 
                                                    int keyusage,
                                                    Date notBefore,
                                                    Date notAfter,
                                                    CertificateProfile certProfile) throws Exception;
    
    public abstract CRL generateCRL(Vector certs, int crlnumber) throws Exception;
    
    public abstract byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException;            
  
        
    public abstract byte[] encryptKeys(KeyPair keypair) throws Exception;
    
    public abstract KeyPair decryptKeys(byte[] data) throws Exception;

    
    // Methods used with extended services	
	/**
	 * Initializes the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public void initExternalService(int type,  CA ca) throws Exception{
		getExtendedCAService(type).init(ca);	    
	}
    	

	/** 
	 * Method used to retrieve information about the service.
	 */

	public ExtendedCAServiceInfo getExtendedCAServiceInfo(int type){
		return getExtendedCAService(type).getExtendedCAServiceInfo();		
	}

	/** 
	 * Method used to perform the service.
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) 
	  throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException{
          ExtendedCAServiceResponse returnval = null; 
          if(request instanceof OCSPCAServiceRequest) {
              returnval = getExtendedCAService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE).extendedService(request);            
          }
          if(request instanceof XKMSCAServiceRequest) {
              returnval = getExtendedCAService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE).extendedService(request);            
          }
          
          if(request instanceof KeyRecoveryCAServiceRequest){
          	KeyRecoveryCAServiceRequest keyrecoveryrequest =  (KeyRecoveryCAServiceRequest) request;
          	if(keyrecoveryrequest.getCommand() == KeyRecoveryCAServiceRequest.COMMAND_ENCRYPTKEYS){
          		try{	
          			returnval = new KeyRecoveryCAServiceResponse(KeyRecoveryCAServiceResponse.TYPE_ENCRYPTKEYSRESPONSE, 
          					encryptKeys(keyrecoveryrequest.getKeyPair()));	
          		}catch(CMSException e){
          			log.error("encrypt:", e.getUnderlyingException());
          			throw new IllegalExtendedCAServiceRequestException(e);
          		}catch(Exception e){
          			throw new IllegalExtendedCAServiceRequestException(e);
          		}
          	}else{
          		if(keyrecoveryrequest.getCommand() == KeyRecoveryCAServiceRequest.COMMAND_DECRYPTKEYS){
                  try{
                  	returnval = new KeyRecoveryCAServiceResponse(KeyRecoveryCAServiceResponse.TYPE_DECRYPTKEYSRESPONSE, 
          					this.decryptKeys(keyrecoveryrequest.getKeyData()));
          		  }catch(CMSException e){
          			 log.error("decrypt:", e.getUnderlyingException());
        		  	 throw new IllegalExtendedCAServiceRequestException(e);
         		  }catch(Exception e){
          		  	 throw new IllegalExtendedCAServiceRequestException(e);
          		  }
          		}else{
          		  throw new IllegalExtendedCAServiceRequestException("Illegal Command"); 
          		}
          	}          	
          }
          
          return returnval;
	}
    
    protected ExtendedCAService getExtendedCAService(int type){
      ExtendedCAService returnval = null;
	  try{
	    returnval = (ExtendedCAService) extendedcaservicemap.get(Integer.valueOf(type));	     		  
        if(returnval == null){
		switch(((Integer) ((HashMap)data.get(EXTENDEDCASERVICE+type)).get(ExtendedCAService.EXTENDEDCASERVICETYPE)).intValue()){
		  case ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE:
		    returnval = new OCSPCAService((HashMap)data.get(EXTENDEDCASERVICE+type));
		    break;	
		  case ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE:
			    returnval = new XKMSCAService((HashMap)data.get(EXTENDEDCASERVICE+type));
			    break;	
		}
		extendedcaservicemap.put(Integer.valueOf(type), returnval);
        }
	  }catch(Exception e){
	  	throw new EJBException(e);  
	  }
    
      return returnval;
    }
    
	protected void setExtendedCAService(ExtendedCAService extendedcaservice){  
      if(extendedcaservice instanceof OCSPCAService){		
	    data.put(EXTENDEDCASERVICE+ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE, extendedcaservice.saveData());    
	    extendedcaservicemap.put(Integer.valueOf(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE), extendedcaservice);
      } 
      if(extendedcaservice instanceof XKMSCAService){		
  	    data.put(EXTENDEDCASERVICE+ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE, extendedcaservice.saveData());    
  	    extendedcaservicemap.put(Integer.valueOf(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE), extendedcaservice);
      } 
	}
	/** 
	 * Returns a Collection of ExternalCAServices (int) added to this CA.
	 *
	 */
		
	public Collection getExternalCAServiceTypes(){
		if(data.get(EXTENDEDCASERVICES) == null)
		  return new ArrayList();
		  		
		return (Collection) data.get(EXTENDEDCASERVICES);	  	 
	}
    
    private HashMap extendedcaservicemap = new HashMap();
    
    private ArrayList certificatechain = null;
    private ArrayList requestcertchain = null;
    
    private CAInfo cainfo = null;

    /**
     * Method to upgrade new (or existing externacaservices)
     * This method needs to be called outside the regular upgrade
     * since the CA isn't instansiated in the regular upgrade.
     *
     */
	public abstract boolean upgradeExtendedCAServices() ;
}