package se.anatom.ejbca.ca.caadmin.extendedcaservices;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.ca.caadmin.CA;
import se.anatom.ejbca.ca.exception.IllegalKeyStoreException;
import se.anatom.ejbca.ca.store.certificateprofiles.OCSPSignerCertificateProfile;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.KeyTools;
/** Handles and maintains the CA -part of the OCSP functionality
 * 
 * @version $Id: OCSPCAService.java,v 1.1 2003-11-02 15:51:37 herrvendil Exp $
 */
public class OCSPCAService extends ExtendedCAService implements java.io.Serializable{

    public static final float LATEST_VERSION = 1; 

    private PrivateKey      ocspsigningkey        = null;
    private List            ocspcertificatechain  = null;
    
    private OCSPCAServiceInfo info = null;  
    
    private static final String OCSPKEYSTORE   = "ocspkeystore"; 
    private static final String KEYSIZE        = "keysize";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";
    
	private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";   
    
            
    public OCSPCAService(OCSPCAServiceInfo info,CA ca) throws Exception {
      data = new HashMap();   
      data.put(EXTENDEDCASERVICETYPE, new Integer(TYPE_OCSPEXTENDEDSERVICE));
                  
      if(info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE)                        
        init(info, ca);
        
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public OCSPCAService(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
      loadData(data);  
      if(data.get(OCSPKEYSTORE) != null){    
         // lookup keystore passwords      
         String privatekeypass = null;
         String keystorepass = null;
         try {
             InitialContext ictx = new InitialContext();
             keystorepass = (String) ictx.lookup("java:comp/env/OCSPKeyStorePass");      
             if (keystorepass == null)
                 throw new IllegalArgumentException("Missing OCSPKeyStorePass property.");
             privatekeypass = (String) ictx.lookup("java:comp/env/privateOCSPKeyPass");
         } catch (NamingException ne) {
             throw new IllegalArgumentException("Missing OCSPKeyStorePass or OCSPPrivateKeyPass property.");
         }
        char[] pkpass = null;
        if ("null".equals(privatekeypass))
            pkpass = null;
        else
            pkpass = privatekeypass.toCharArray();
               
        try {
            KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(OCSPKEYSTORE)).getBytes())),keystorepass.toCharArray());
      
            this.ocspsigningkey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, pkpass);
            this.ocspcertificatechain =  Arrays.asList(keystore.getCertificateChain(PRIVATESIGNKEYALIAS));      
            this.info = new OCSPCAServiceInfo(getStatus(),
                                              (String) data.get(SUBJECTDN),
                                              (String) data.get(SUBJECTALTNAME), 
                                              ((Integer) data.get(KEYSIZE)).intValue(), 
                                              (String) data.get(KEYALGORITHM));
      
        } catch (Exception e) {
            throw new IllegalKeyStoreException(e);
        }
        
        data.put(EXTENDEDCASERVICETYPE, new Integer(TYPE_OCSPEXTENDEDSERVICE));        
     } 
   }
    
    

   /* 
	* @see se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void init(ExtendedCAServiceInfo serviceinfo, CA ca) throws Exception{
	 // lookup keystore passwords      
	 InitialContext ictx = new InitialContext();
	 String keystorepass = (String) ictx.lookup("java:comp/env/OCSPKeyStorePass");      
	 if (keystorepass == null)
	   throw new IllegalArgumentException("Missing privateOCSPKeyPass property.");
        
	 String privatekeypass = (String) ictx.lookup("java:comp/env/privateOCSPKeyPass");
	 char[] pkpass = null;
	 if ((privatekeypass).equals("null"))
	   pkpass = null;
	 else
	   pkpass = privatekeypass.toCharArray();       
       
	  // Currently only RSA keys are supported
	 OCSPCAServiceInfo info = (OCSPCAServiceInfo) serviceinfo;       
                  
	 // Create OSCP KeyStore	    
     int keysize = info.getKeySize();  
	 KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
	 keystore.load(null, null);                              
      
	 KeyPair ocspkeys = KeyTools.genKeys(info.getKeySize());
	   	  
	 Certificate ocspcertificate =
	  ca.generateCertificate(new UserAuthData("NOUSERNAME", 	                                          
											info.getSubjectDN(),
											0, 
											info.getSubjectAltName(),
											"NOEMAIL",
											0,0)
						   , ocspkeys.getPublic(),
						   0, 
						   new OCSPSignerCertificateProfile());
	  
     ArrayList oscpcertchain = new ArrayList();
     oscpcertchain.add(ocspcertificate);
     oscpcertchain.addAll(ca.getCertificateChain());
      	  	 	  
	  	  	  
     keystore.setKeyEntry(PRIVATESIGNKEYALIAS,ocspkeys.getPrivate(),pkpass,(Certificate[]) oscpcertchain.toArray(new Certificate[oscpcertchain.size()]));              
     java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
     keystore.store(baos, keystorepass.toCharArray());
     data.put(OCSPKEYSTORE, new String(Base64.encode(baos.toByteArray())));      
     // Store OCSP KeyStore
      
     data.put(KEYSIZE, new Integer(info.getKeySize()));
     data.put(KEYALGORITHM, info.getKeyAlgorithm());
	 data.put(SUBJECTDN, info.getSubjectDN());
	 data.put(SUBJECTALTNAME, info.getSubjectAltName());
	 setStatus(ExtendedCAServiceInfo.STATUS_ACTIVE);
	 this.info = new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
									  (String) data.get(SUBJECTDN),
									  (String) data.get(SUBJECTALTNAME), 
									  ((Integer) data.get(KEYSIZE)).intValue(), 
									  (String) data.get(KEYALGORITHM));
      
   }   

   /* 
	* @see se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void activate(){
	 setStatus(ExtendedCAServiceInfo.STATUS_ACTIVE);
	 this.info = new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
										  (String) data.get(SUBJECTDN),
										  (String) data.get(SUBJECTALTNAME), 
										  ((Integer) data.get(KEYSIZE)).intValue(), 
										  (String) data.get(KEYALGORITHM));
   }   

   /* 
	* @see se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void deactivate(){
   	 setStatus(ExtendedCAServiceInfo.STATUS_INACTIVE);
	 this.info = new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
									   (String) data.get(SUBJECTDN),
									   (String) data.get(SUBJECTALTNAME), 
									   ((Integer) data.get(KEYSIZE)).intValue(), 
									   (String) data.get(KEYALGORITHM));
   }   


	/* 
	 * @see se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
		if(!(request instanceof OCSPCAServiceRequest))
		  throw new IllegalExtendedCAServiceRequestException();
		  		
		return (ExtendedCAServiceResponse) new OCSPCAServiceResponse(this.ocspcertificatechain,this.ocspsigningkey);
	}

	
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
		if(LATEST_VERSION != getVersion()){
		  // New version of the class, upgrade

		  data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}

	/* 
	 * @see se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAService#getExtendedCAServiceInfo()
	 */
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {		
		return this.info;
	}
    
    
}

