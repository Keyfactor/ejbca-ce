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
 
package se.anatom.ejbca.ca.caadmin;

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

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAService;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceResponse;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAService;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import se.anatom.ejbca.ca.exception.IllegalKeyStoreException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.UpgradeableDataHashMap;

/**
 * CA is a base class that should be inherited by all CA types
 *
 * @version $Id: CA.java,v 1.10 2004-05-10 04:35:10 herrvendil Exp $
 */
public abstract class CA extends UpgradeableDataHashMap implements Serializable {


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
    protected static final String CRLPUBLISHERS                  = "crlpublishers";
	protected static final String FINISHUSER                     = "finishuser";
	protected static final String REQUESTCERTCHAIN               = "requestcertchain";
	protected static final String EXTENDEDCASERVICES             = "extendedcaservices";
	protected static final String EXTENDEDCASERVICE              = "extendedcaservice";
    
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
       setCRLPublishers(cainfo.getCRLPublishers());
       setFinishUser(cainfo.getFinishUser());
       
	   extendedcaservicemap = new HashMap();
	   Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
	   ArrayList extendedservicetypes = new ArrayList(); 
	   while(iter.hasNext()){
	   	 ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();
	   	 if(next instanceof OCSPCAServiceInfo){
	   	   setExtendedCAService(new OCSPCAService(next));
	   	   extendedservicetypes.add(new Integer(OCSPCAService.TYPE));
	   	 }
	   }
	   data.put(EXTENDEDCASERVICES, extendedservicetypes);
    }
    
    /** Constructor used when retrieving existing CA from database. */
    public CA(HashMap data, CADataBean owner){
      loadData(data);
      this.owner = owner;
      
	  extendedcaservicemap = new HashMap();
    }

    // Public Methods.
    public String getSubjectDN(){
    	if(owner == null)
      	  return cainfo.getSubjectDN();
    	
    	return owner.getSubjectDN();
    }
    
    public int getCAId(){
    	if(owner == null)
    		return cainfo.getCAId();
    	
    	return owner.getCAId().intValue();
    }    
    
    public int getCAType(){ return ((Integer)data.get(CATYPE)).intValue();}
    
    public String getName(){
    	if(owner == null)
    	  return cainfo.getName();
    	
    	return owner.getName();
    }
    
    public void setName(String name) { owner.setName(name);}

    public int getStatus(){
    	    	    	
    	if(owner == null)
      	  return cainfo.getStatus();	
    	
    	return owner.getStatus();
    }
    
    public void setStatus(int status) {     	
    	owner.setStatus(status);    	
    }    
    
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
    
    public Collection  getCRLPublishers(){return ((Collection)data.get(CRLPUBLISHERS));}
    public void setCRLPublishers(Collection crlpublishers) {data.put(CRLPUBLISHERS, crlpublishers);}    
    
    
    public int getCertificateProfileId() {return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();}
    
    public CAToken getCAToken() throws IllegalKeyStoreException {
      if(catoken == null){            

      	      	
        switch(((Integer) ((HashMap)data.get(CATOKENDATA)).get(CAToken.CATOKENTYPE)).intValue()){
            case CATokenInfo.CATOKENTYPE_P12:
              catoken = (CAToken) new SoftCAToken((HashMap)data.get(CATOKENDATA));
              break;
            case CATokenInfo.CATOKENTYPE_HSM:
              catoken = (CAToken) new HardCATokenContainer((HashMap)data.get(CATOKENDATA)); 
              break;
            case CATokenInfo.CATOKENTYPE_NULL:
              catoken = new NullCAToken();  
        }
      }
      return catoken;
    }    
        
    public void setCAToken(CAToken catoken){
       data.put(CATOKENDATA, (HashMap) catoken.saveData());        
       this.catoken = catoken;
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
        
      return (Collection) requestcertchain; 
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

	public Collection getCertificateChain(){
	  if(certificatechain == null){
		Collection storechain = (Collection) data.get(CERTIFICATECHAIN);
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
        
	  return (Collection) certificatechain; 
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

    
    public Certificate getCACertificate(){       
       if(certificatechain == null){
         getCertificateChain();
       }
              
       return (Certificate) this.certificatechain.get(0);
    }
    
	public boolean  getFinishUser(){return ((Boolean)data.get(FINISHUSER)).booleanValue();}
	
	public void setFinishUser(boolean finishuser) {data.put(FINISHUSER, new Boolean(finishuser));}    
    
    public void updateCA(CAInfo cainfo) throws Exception{            
      data.put(VALIDITY, new Integer(cainfo.getValidity()));                 
      data.put(DESCRIPTION, cainfo.getDescription());      
      data.put(CRLPERIOD, new Integer(cainfo.getCRLPeriod()));
	  data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
	  getCAToken().updateCATokenInfo(cainfo.getCATokenInfo());
      setFinishUser(cainfo.getFinishUser());
      
      Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
      while(iter.hasNext()){
      	ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
      	if(info instanceof OCSPCAServiceInfo){
      	  this.getExtendedCAService(OCSPCAService.TYPE).update(info, this);	
      	}
      }
    }
    
    public abstract CAInfo getCAInfo() throws Exception;
    
    public Certificate  generateCertificate(UserAuthData subject, 
                                            PublicKey publicKey, 
                                            int keyusage,                                             
                                            CertificateProfile certProfile) throws Exception{
      return generateCertificate(subject, publicKey, keyusage, -1, certProfile);                                            
    }
    
    
    public abstract Certificate generateCertificate(UserAuthData subject, 
                                                    PublicKey publicKey, 
                                                    int keyusage, 
                                                    long validity,
                                                    CertificateProfile certProfile) throws Exception;
    
    public abstract CRL generateCRL(Vector certs, int crlnumber) throws Exception;
    
    public abstract byte[] createPKCS7(Certificate cert) throws SignRequestSignatureException;            
  
        
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
              returnval = getExtendedCAService(OCSPCAService.TYPE).extendedService(request);            
          }
          
          if(request instanceof KeyRecoveryCAServiceRequest){
          	KeyRecoveryCAServiceRequest keyrecoveryrequest =  (KeyRecoveryCAServiceRequest) request;
          	if(keyrecoveryrequest.getCommand() == KeyRecoveryCAServiceRequest.COMMAND_ENCRYPTKEYS){
          	  try{	
          	    returnval = new KeyRecoveryCAServiceResponse(KeyRecoveryCAServiceResponse.TYPE_ENCRYPTKEYSRESPONSE, 
          	  		                       encryptKeys(keyrecoveryrequest.getKeyPair()));	
          	  }catch(Exception e){
          	  	 throw new IllegalExtendedCAServiceRequestException(e.getClass().getName() + " : " + e.getMessage());
          	  }
          	}else{
          		if(keyrecoveryrequest.getCommand() == KeyRecoveryCAServiceRequest.COMMAND_DECRYPTKEYS){
                  try{
                  	returnval = new KeyRecoveryCAServiceResponse(KeyRecoveryCAServiceResponse.TYPE_DECRYPTKEYSRESPONSE, 
          					this.decryptKeys(keyrecoveryrequest.getKeyData()));
          		  }catch(Exception e){
          		  	 throw new IllegalExtendedCAServiceRequestException(e.getClass().getName() + " : " + e.getMessage());
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
	    returnval = (ExtendedCAService) extendedcaservicemap.get(new Integer(type));	     		  
        if(returnval == null){
		switch(((Integer) ((HashMap)data.get(EXTENDEDCASERVICE+type)).get(ExtendedCAService.EXTENDEDCASERVICETYPE)).intValue()){
		  case ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE:
		    returnval = new OCSPCAService((HashMap)data.get(EXTENDEDCASERVICE+type));
		    break;		    
		}
		extendedcaservicemap.put(new Integer(type), returnval);
        }
	  }catch(Exception e){
	  	throw new EJBException(e);  
	  }
    
      return returnval;
    }
    
	protected void setExtendedCAService(ExtendedCAService extendedcaservice){  
      if(extendedcaservice instanceof OCSPCAService){		
	    data.put(EXTENDEDCASERVICE+OCSPCAService.TYPE, (HashMap) extendedcaservice.saveData());    
	    extendedcaservicemap.put(new Integer(OCSPCAService.TYPE), extendedcaservice);
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
    
	public void setOwner(CADataBean owner){
	  this.owner = owner;	
	}
    
    private CAToken catoken = null;
    private HashMap extendedcaservicemap = null;
    private ArrayList certificatechain = null;
    private ArrayList requestcertchain = null;
    
    private CADataBean owner = null;
    private CAInfo cainfo = null;
}
