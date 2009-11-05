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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceRequest;
import org.ejbca.core.model.ca.catoken.CATokenContainer;
import org.ejbca.core.model.ca.catoken.CATokenContainerImpl;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.CATokenManager;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.NullCATokenInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.ValidityDate;




/**
 * CA is a base class that should be inherited by all CA types
 *
 * @version $Id$
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
    protected static final String DELTACRLPERIOD                 = "deltacrlperiod";
    protected static final String CRLISSUEINTERVAL               = "crlIssueInterval";
    protected static final String CRLOVERLAPTIME                 = "crlOverlapTime";
    protected static final String CRLPUBLISHERS                  = "crlpublishers";
	protected static final String FINISHUSER                     = "finishuser";
	protected static final String REQUESTCERTCHAIN               = "requestcertchain";
	protected static final String EXTENDEDCASERVICES             = "extendedcaservices";
	protected static final String EXTENDEDCASERVICE              = "extendedcaservice";
	protected static final String APPROVALSETTINGS               = "approvalsettings";
	protected static final String NUMBEROFREQAPPROVALS           = "numberofreqapprovals";
	protected static final String INCLUDEINHEALTHCHECK			 = "includeinhealthcheck";
    
    // Public Methods
    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public CA(CAInfo cainfo){
       data = new HashMap();
       
       this.cainfo = cainfo;
              
       data.put(VALIDITY, new Long(cainfo.getValidity()));
       data.put(SIGNEDBY, new Integer(cainfo.getSignedBy()));
       data.put(DESCRIPTION, cainfo.getDescription());
       data.put(REVOKATIONREASON, new Integer(-1));
       data.put(CERTIFICATEPROFILEID, new Integer(cainfo.getCertificateProfileId()));
       setCRLPeriod(cainfo.getCRLPeriod());
       setCRLIssueInterval(cainfo.getCRLIssueInterval());
       setCRLOverlapTime(cainfo.getCRLOverlapTime());
       setDeltaCRLPeriod(cainfo.getDeltaCRLPeriod());
       setCRLPublishers(cainfo.getCRLPublishers());
       setFinishUser(cainfo.getFinishUser());
       setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
	   
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
	   	 if(next instanceof CmsCAServiceInfo){
			   setExtendedCAService(new CmsCAService(next));
			   extendedservicetypes.add(new Integer(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE));
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
    
    public long getValidity(){ return ((Number) data.get(VALIDITY)).longValue();}
    public void setValidity(long validity){ data.put(VALIDITY,  new Long(validity));}
    
    public Date getExpireTime(){return ((Date)data.get(EXPIRETIME));}
    public void setExpireTime(Date expiretime) { data.put(EXPIRETIME,expiretime);}    
   
    public int getSignedBy(){ return ((Integer) data.get(SIGNEDBY)).intValue();}
    
    public String getDescription(){return ((String)data.get(DESCRIPTION));}
    public void setDescription(String description) { data.put(DESCRIPTION,description);}  
    
    public int getRevokationReason(){return ((Integer) data.get(REVOKATIONREASON)).intValue();}
    public void setRevokationReason(int reason){ data.put(REVOKATIONREASON,new Integer(reason));}
        
	public Date getRevokationDate(){return (Date) data.get(REVOKATIONDATE);}
	public void setRevokationDate(Date date){ data.put(REVOKATIONDATE,date);}
                
    public long getCRLPeriod(){return ((Long)data.get(CRLPERIOD)).longValue();}
    public void setCRLPeriod(long crlperiod) {data.put(CRLPERIOD, new Long(crlperiod));}
    
    public long getDeltaCRLPeriod() {
    	if(data.containsKey(DELTACRLPERIOD)) {
    		return ((Long)data.get(DELTACRLPERIOD)).longValue();
    	} else {
    		return 0;
    	}
    }
    public void setDeltaCRLPeriod(long deltacrlperiod) {data.put(DELTACRLPERIOD, new Long(deltacrlperiod));}
    	
    public long getCRLIssueInterval(){return ((Long)data.get(CRLISSUEINTERVAL)).longValue();}
    public void setCRLIssueInterval(long crlIssueInterval) {data.put(CRLISSUEINTERVAL, new Long(crlIssueInterval));}
    
    public long getCRLOverlapTime(){return ((Long)data.get(CRLOVERLAPTIME)).longValue();}
    public void setCRLOverlapTime(long crlOverlapTime) {data.put(CRLOVERLAPTIME, new Long(crlOverlapTime));}

    public Collection  getCRLPublishers(){return ((Collection)data.get(CRLPUBLISHERS));}
    public void setCRLPublishers(Collection crlpublishers) {data.put(CRLPUBLISHERS, crlpublishers);}    
    
    
    public int getCertificateProfileId() {return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();}
    
    /** Returns the CAs token. The token is fetched from the token registry, or created and added to the token registry.
     * 
     * @return The CAs token, be it soft or hard.
     * @throws IllegalKeyStoreException If the token keystore is invalid (crypto error thrown by crypto provider), or the CA token type is undefined.
     */
    public CATokenContainer getCAToken(int caid) throws IllegalKeyStoreException {
        CATokenContainer ret = CATokenManager.instance().getCAToken(caid);
        if (ret == null) {
        	Integer tokentype = (Integer) ((HashMap)data.get(CATOKENDATA)).get(CATokenContainer.CATOKENTYPE);
            switch(tokentype.intValue()) {
            case CATokenInfo.CATOKENTYPE_P12:
                ret = new CATokenContainerImpl((HashMap)data.get(CATOKENDATA), caid); 
                break;
            case CATokenInfo.CATOKENTYPE_HSM:
                ret = new CATokenContainerImpl((HashMap)data.get(CATOKENDATA), caid);
                break;
            case CATokenInfo.CATOKENTYPE_NULL:
            	NullCATokenInfo info = new NullCATokenInfo();
                ret = new CATokenContainerImpl(info, caid);
                break;
            default:
                throw new IllegalKeyStoreException("No CA Token type defined: "+tokentype.intValue());
            }
            CATokenManager.instance().addCAToken(caid, ret);
        }            
      return ret;    	
    }
    /** Returns the CAs token. The token is fetched from the token registry, or created and added to the token registry.
     * 
     * @return The CAs token, be it soft or hard.
     * @throws IllegalKeyStoreException If the token keystore is invalid (crypto error thrown by crypto provider), or the CA token type is undefined.
     */
    public CATokenContainer getCAToken() throws IllegalKeyStoreException {
    	return getCAToken(getCAId());
    }    
        
    /** Sets the CA token. Adds or updates the token in the token registry.
     * 
     * @param catoken The CAs token, be it soft or hard.
     */
    public void setCAToken(CATokenContainer catoken){
       data.put(CATOKENDATA, catoken.saveData());        
       CATokenManager.instance().addCAToken(getCAId(), catoken);
    }
    
    /** Returns a collection of CA certificates, or null if no request certificate chain exists
     */
    public Collection getRequestCertificateChain(){
    	if(requestcertchain == null){
    		Collection storechain = (Collection) data.get(REQUESTCERTCHAIN);
    		if (storechain != null) {
    			Iterator iter = storechain.iterator();
    			this.requestcertchain = new ArrayList();
    			while(iter.hasNext()){
    				String b64Cert = (String) iter.next();
    				try {
    					this.requestcertchain.add(CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes())));
    				} catch(Exception e) {
    					throw new RuntimeException(e);   
    				}
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
          throw new RuntimeException(e);  
        }  
      }
      data.put(REQUESTCERTCHAIN,storechain);  
      
      this.requestcertchain = new ArrayList();
      this.requestcertchain.addAll(requestcertificatechain);
    }

    /** Returns a collection of CA-certificates, with this CAs cert i position 0, or null
     * if no CA-certificates exist. The root CA certificate will thus be in the last position.
     * @return Collection of Certificate
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
			  Certificate cert = CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes()));
			  if (cert != null) {
			       if (log.isDebugEnabled()) {
			    	   log.debug("Adding CA certificate from CERTIFICATECHAIN to certificatechain:");
			    	   log.debug("Cert subjectDN: "+CertTools.getSubjectDN(cert));
			    	   log.debug("Cert issuerDN: "+CertTools.getIssuerDN(cert));
			       }				  
				  this.certificatechain.add(cert);				  
			  } else {
				  throw new IllegalArgumentException("Can not create certificate object from: "+b64Cert);
			  }
		  }catch(Exception e){
			 throw new RuntimeException(e);   
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
		  throw new RuntimeException(e);  
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
       if (certificatechain.size() == 0) {
    	   return null;
       }
       Certificate ret = (Certificate) certificatechain.get(0);
       if (log.isDebugEnabled()) {
    	   log.debug("CA certificate chain is "+certificatechain.size()+" levels deep.");
    	   log.debug("CA-cert subjectDN: "+CertTools.getSubjectDN(ret));
    	   log.debug("CA-cert issuerDN: "+CertTools.getIssuerDN(ret));
       }
       return ret;
    }
    
	public boolean  getFinishUser(){return ((Boolean)data.get(FINISHUSER)).booleanValue();}
	
	public void setFinishUser(boolean finishuser) {data.put(FINISHUSER, new Boolean(finishuser));}   
	
	public boolean  getIncludeInHealthCheck(){
		Boolean temp = ((Boolean)data.get(INCLUDEINHEALTHCHECK)).booleanValue();
		if (temp != null) {
			return temp;
		} 
		return true;
	}
	
	public void setIncludeInHealthCheck(boolean includeInHealthCheck) {
			data.put(INCLUDEINHEALTHCHECK, new Boolean(includeInHealthCheck)); 
	}
    
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
    	data.put(VALIDITY, new Long(cainfo.getValidity()));                 
    	data.put(DESCRIPTION, cainfo.getDescription());      
    	data.put(CRLPERIOD, new Long(cainfo.getCRLPeriod()));
    	data.put(DELTACRLPERIOD, new Long(cainfo.getDeltaCRLPeriod()));
    	data.put(CRLISSUEINTERVAL, new Long(cainfo.getCRLIssueInterval()));
    	data.put(CRLOVERLAPTIME, new Long(cainfo.getCRLOverlapTime()));
    	data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
    	data.put(APPROVALSETTINGS,cainfo.getApprovalSettings());
        data.put(NUMBEROFREQAPPROVALS,new Integer(cainfo.getNumOfReqApprovals()));
        if (cainfo.getCertificateProfileId() > 0) {
            data.put(CERTIFICATEPROFILEID,new Integer(cainfo.getCertificateProfileId()));        	
        }
    	CATokenContainer token = getCAToken();
    	if (token != null) {
    		token.updateCATokenInfo(cainfo.getCATokenInfo());
    		setCAToken(token);
    	}
    	setFinishUser(cainfo.getFinishUser());
    	setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
    	
    	Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
    	while(iter.hasNext()){
    		ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) iter.next();
    		if(info instanceof OCSPCAServiceInfo){
    			this.getExtendedCAService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE).update(info, this);	
    		}
    		if(info instanceof XKMSCAServiceInfo){
    			this.getExtendedCAService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE).update(info, this);	
    		}
    		if(info instanceof CmsCAServiceInfo){
    			this.getExtendedCAService(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE).update(info, this);	
    		}
    	}
    	this.cainfo = cainfo;
    }
    
    
    /**
     * 
     * @param subject
     * @param publicKey
     * @param keyusage
     * @param validity requested validity in days
     * @param certProfile
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by CVC CAs for sequence field. Can be set to null.
     * @return
     * @throws Exception
     */
    public Certificate generateCertificate(UserDataVO subject,
            PublicKey publicKey, 
            int keyusage, 
            long validity,
            CertificateProfile certProfile,
            String sequence) throws Exception {
    	// Calculate the notAfter date
        final Date notBefore = new Date(); 
    	final Date notAfter;
        if(validity != -1) {
            notAfter = ValidityDate.getDate(validity, notBefore);
        } else {
            notAfter = null;
        }
    	return generateCertificate(subject, null, publicKey, keyusage, notBefore, notAfter, certProfile, null, sequence); 
    }

    /**
     * 
     * @param subject
     * @param publicKey
     * @param keyusage
     * @param notBefore
     * @param notAfter
     * @param certProfile
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by CVC CAs for sequence field. Can be set to null.
     * @return
     * @throws Exception
     */
    public abstract Certificate generateCertificate(UserDataVO subject, 
                                             		X509Name requestX509Name,
                                                    PublicKey publicKey, 
                                                    int keyusage,
                                                    Date notBefore,
                                                    Date notAfter,
                                                    CertificateProfile certProfile,
                                                    X509Extensions extensions,
                                                    String sequence) throws Exception;
    
    public abstract CRL generateCRL(Collection certs, int crlnumber) throws Exception;
    
    public abstract CRL generateDeltaCRL(Collection certs, int crlnumber, int basecrlnumber) throws Exception;

    public abstract byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException;            

    /** Creates a certificate signature request CSR), that can be sent to an external Root CA. Request format can vary depending on the type of CA.
     * For X509 CAs PKCS#10 requests are created, for CVC CAs CVC requests are created.
     * 
     * @param attributes PKCS10 attributes to be included in the request, a Collection of DEREncodable objects, ready to put in the request. Can be null.
     * @param signAlg the signature algorithm used by the CA
     * @param cacert the CAcertficate the request is targeted for, may be used or ignored by implementation depending on the request type created.
     * @return byte array with binary encoded request
     */
    public abstract byte[] createRequest(Collection attributes, String signAlg, Certificate cacert) throws CATokenOfflineException;

    /** Signs a certificate signature request CSR), that can be sent to an external CA. This signature can be use to authenticate the 
     * original request. mainly used for CVC CAs where the CVC requests is created and (self)signed by the DV and then the CVCA
     * adds an outer signature to the request.
     * The signature algorithm used to sign the request will be whatever algorithm the CA uses to sign certificates.
     * 
     * @param request the binary coded request to be signed
     * @param usepreviouskey true if the CAs previous key should be used to sign the request, if the CA has generated new keys. Primarily used to create authenticated CVC requests.
     * @param createlinkcert true if the signed request should be a link certificate. Primarily used to create CVC link certificates.
     * @return byte array with binary encoded signed request or the original request of the CA can not create an additional signature on the passed in request.
     */
    public abstract byte[] signRequest(byte[] request, boolean usepreviouskey, boolean createlinkcert) throws CATokenOfflineException;

    public byte[] encryptKeys(KeyPair keypair) throws Exception{
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream os = new ObjectOutputStream(baos);
    	os.writeObject(keypair); 
    	return encryptData(baos.toByteArray(), SecConst.CAKEYPURPOSE_KEYENCRYPT);
    }
    
    public KeyPair decryptKeys(byte[] data) throws Exception{
    	byte[] recdata = decryptData(data,SecConst.CAKEYPURPOSE_KEYENCRYPT);
    	ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(recdata));    	
    	return (KeyPair) ois.readObject();  
    }
    /**
     * General encryption method used to encrypt using a CA
     * @param data the data to encrypt
     * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
     * @return encrypted data
     */
    public abstract byte[] encryptData(byte[] data, int keyPurpose) throws Exception;
    
    /**
     * General encryption method used to decrypt using a CA
     * @param data the data to decrypt
     * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
     * @return decrypted data
     */
    public abstract byte[] decryptData(byte[] data, int cAKeyPurpose) throws Exception;

    
    // Methods used with extended services	
	/**
	 * Initializes the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public void initExternalService(int type,  CA ca) throws Exception{
		ExtendedCAService service = getExtendedCAService(type);
		if (service != null) {
			service.init(ca);
		}
	}
    	

	/** 
	 * Method used to retrieve information about the service.
	 */

	public ExtendedCAServiceInfo getExtendedCAServiceInfo(int type){
		ExtendedCAServiceInfo ret = null;
		ExtendedCAService service = getExtendedCAService(type);
		if (service != null) {
			ret = service.getExtendedCAServiceInfo();
		}
		return ret;		
	}

	/** 
	 * Method used to perform the service.
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) 
	  throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException{
          ExtendedCAServiceResponse returnval = null; 
          if(request instanceof OCSPCAServiceRequest) {
        	  OCSPCAServiceRequest ocspServiceReq = (OCSPCAServiceRequest)request;
              boolean useCACert = ocspServiceReq.useCACert();
              try {
                  if (useCACert) {
                	  ocspServiceReq.setPrivKey(getCAToken().getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN));
                	  ocspServiceReq.setPrivKeyProvider(getCAToken().getProvider());
                	  X509Certificate[] signerChain = (X509Certificate[])getCertificateChain().toArray(new X509Certificate[0]);
                	  List chain = Arrays.asList(signerChain);
                	  ocspServiceReq.setCertificateChain(chain);
                      // Super class handles signing with the OCSP signing certificate
                      log.debug("extendedService, with ca cert)");
                  } else {
                      // Super class handles signing with the OCSP signing certificate
                      log.debug("extendedService, no ca cert)");
                  }
              } catch (IllegalKeyStoreException ike) {
            	  throw new ExtendedCAServiceRequestException(ike);
              } catch (CATokenOfflineException ctoe) {
            	  throw new ExtendedCAServiceRequestException(ctoe);
              } catch (IllegalArgumentException e) {
            	  log.error("IllegalArgumentException: ", e);
            	  throw new IllegalExtendedCAServiceRequestException(e);
              }
              returnval = getExtendedCAService(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE).extendedService(ocspServiceReq);            
          }
          if(request instanceof XKMSCAServiceRequest) {
              returnval = getExtendedCAService(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE).extendedService(request);            
          }
          if(request instanceof CmsCAServiceRequest) {
              returnval = getExtendedCAService(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE).extendedService(request);            
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
          if(request instanceof HardTokenEncryptCAServiceRequest){
        	  HardTokenEncryptCAServiceRequest hardencrequest =  (HardTokenEncryptCAServiceRequest) request;
            	if(hardencrequest.getCommand() == HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA){
            		try{	
            			returnval = new HardTokenEncryptCAServiceResponse(HardTokenEncryptCAServiceResponse.TYPE_ENCRYPTRESPONSE, 
            					encryptData(hardencrequest.getData(), SecConst.CAKEYPURPOSE_HARDTOKENENCRYPT));	
            		}catch(CMSException e){
            			log.error("encrypt:", e.getUnderlyingException());
            			throw new IllegalExtendedCAServiceRequestException(e);
            		}catch(Exception e){
            			throw new IllegalExtendedCAServiceRequestException(e);
            		}
            	}else{
            		if(hardencrequest.getCommand() == HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA){
                    try{
                    	returnval = new HardTokenEncryptCAServiceResponse(HardTokenEncryptCAServiceResponse.TYPE_DECRYPTRESPONSE, 
            					this.decryptData(hardencrequest.getData(), SecConst.CAKEYPURPOSE_HARDTOKENENCRYPT));
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
	    returnval = (ExtendedCAService) extendedcaservicemap.get(new Integer(type));	     		  
        if(returnval == null) {
        	switch(((Integer) ((HashMap)data.get(EXTENDEDCASERVICE+type)).get(ExtendedCAService.EXTENDEDCASERVICETYPE)).intValue()) {
	        	case ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE:
	        		returnval = new OCSPCAService((HashMap)data.get(EXTENDEDCASERVICE+type));
	        		break;	
	        	case ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE:
	        		returnval = new XKMSCAService((HashMap)data.get(EXTENDEDCASERVICE+type));
	        		break;	
	        	case ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE:
	        		returnval = new CmsCAService((HashMap)data.get(EXTENDEDCASERVICE+type));
	        		break;	
        	}
		extendedcaservicemap.put(new Integer(type), returnval);
        }
	  }catch(Exception e){
	  	throw new RuntimeException(e);  
	  }
    
      return returnval;
    }
    
    protected void setExtendedCAService(ExtendedCAService extendedcaservice) {  
    	if(extendedcaservice instanceof OCSPCAService){		
    		data.put(EXTENDEDCASERVICE+ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE, extendedcaservice.saveData());    
    		extendedcaservicemap.put(new Integer(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE), extendedcaservice);
    	} 
    	if(extendedcaservice instanceof XKMSCAService){		
    		data.put(EXTENDEDCASERVICE+ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE, extendedcaservice.saveData());    
    		extendedcaservicemap.put(new Integer(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE), extendedcaservice);
    	} 
    	if(extendedcaservice instanceof CmsCAService){		
    		data.put(EXTENDEDCASERVICE+ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE, extendedcaservice.saveData());    
    		extendedcaservicemap.put(new Integer(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE), extendedcaservice);
    	} 
    }
	/** 
	 * Returns a Collection of ExternalCAServices (int) added to this CA.
	 *
	 */
		
	public Collection getExternalCAServiceTypes(){
		if(data.get(EXTENDEDCASERVICES) == null) {
		  return new ArrayList();
		}
		return (Collection) data.get(EXTENDEDCASERVICES);	  	 
	}
    
    private HashMap extendedcaservicemap = new HashMap();
    
    private ArrayList certificatechain = null;
    private ArrayList requestcertchain = null;
    
    private CAInfo cainfo = null;

    /**
     * Method to upgrade new (or existing externacaservices)
     * This method needs to be called outside the regular upgrade
     * since the CA isn't instantiated in the regular upgrade.
     *
     */
	public abstract boolean upgradeExtendedCAServices() ;
}