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

import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.exception.IllegalKeyStoreException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.UpgradeableDataHashMap;

/**
 * CA is a base class that should be inherited by all CA types
 *
 * @version $Id: CA.java,v 1.5 2003-10-21 13:48:45 herrvendil Exp $
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
	protected static final String REVOKATIONDATE                   = "revokationdate";
    protected static final String CERTIFICATEPROFILEID           = "certificateprofileid";
    protected static final String CRLPERIOD                      = "crlperiod";
    protected static final String CRLPUBLISHERS                  = "crlpublishers";
	protected static final String FINISHUSER                     = "finishuser";
	protected static final String REQUESTCERTCHAIN        = "requestcertchain";
    
    // Public Methods
    /** Creates a new instance of CA, this constuctor should be used when a new CA is created */
    public CA(CAInfo cainfo){
       data = new HashMap();
       data.put(SUBJECTDN, CertTools.stringToBCDNString(cainfo.getSubjectDN()));
       data.put(NAME, cainfo.getName());
       data.put(STATUS, new Integer(cainfo.getStatus()));
       data.put(VALIDITY, new Integer(cainfo.getValidity()));
       data.put(EXPIRETIME,  cainfo.getExpireTime());
       data.put(SIGNEDBY, new Integer(cainfo.getSignedBy()));
       data.put(DESCRIPTION, cainfo.getDescription());
       data.put(REVOKATIONREASON, new Integer(-1));
       data.put(CERTIFICATEPROFILEID, new Integer(cainfo.getCertificateProfileId()));
       setCRLPeriod(cainfo.getCRLPeriod());
       setCRLPublishers(cainfo.getCRLPublishers());
       setFinishUser(cainfo.getFinishUser());
    }
    
    /** Constructor used when retrieving existing CA from database. */
    public CA(HashMap data, String name, int status, Date expiretime){
      loadData(data);
      data.put(NAME, name);
      setStatus(status);
      setExpireTime(expiretime);
    }

    // Public Methods.
    public String getSubjectDN(){return ((String)data.get(SUBJECTDN));}
    
    public int getCAId(){return ((String)data.get(SUBJECTDN)).hashCode();}    
    
    public int getCAType(){ return ((Integer)data.get(CATYPE)).intValue();}
    
    public String getName(){return  ((String)data.get(NAME));}
    public void setName(String name) {data.put(NAME, name);}

    public int getStatus(){return ((Integer)data.get(STATUS)).intValue();}
    public void setStatus(int status) { data.put(STATUS,new Integer(status));}    
    
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
    
    public void updateCA(CAInfo cainfo){            
      data.put(VALIDITY, new Integer(cainfo.getValidity()));                 
      data.put(DESCRIPTION, cainfo.getDescription());      
      data.put(CRLPERIOD, new Integer(cainfo.getCRLPeriod()));
	  data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
      this.catoken.updateCATokenInfo(cainfo.getCATokenInfo());
      setFinishUser(cainfo.getFinishUser());
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
  
        
    public byte[] encryptKeys(KeyPair keypair){
		// TODO, encryptKeys       
       return null; 
    }
    
    public KeyPair decryptKeys(byte[] data){
      // TODO, decryptKeys
      return null;  
    }
    

    
    private CAToken catoken = null;
    private ArrayList certificatechain = null;
    private ArrayList requestcertchain = null;

}
