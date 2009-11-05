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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.certificateprofiles.OCSPSignerCertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;



/** Handles and maintains the CA-part of the OCSP functionality
 * 
 * @version $Id$
 */
public class OCSPCAService extends ExtendedCAService implements java.io.Serializable{

    private static Logger m_log = Logger.getLogger(OCSPCAService.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final float LATEST_VERSION = 2; 
    
    public static final String SERVICENAME = "OCSPCASERVICE";
      

    private PrivateKey      ocspsigningkey        = null;
    private List            ocspcertificatechain  = null;
    
    private OCSPCAServiceInfo info = null;  
    
    private static final String OCSPKEYSTORE   = "ocspkeystore"; 
    private static final String KEYSPEC        = "keyspec";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";
    
	private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";   

	/** kept for upgrade purposes 3.3 -> 3.4 */
    private static final String KEYSIZE        = "keysize";
            
    public OCSPCAService(ExtendedCAServiceInfo serviceinfo)  {
      m_log.debug("OCSPCAService : constructor " + serviceinfo.getStatus()); 
      CertTools.installBCProvider();
	  // Currently only RSA keys are supported
	  OCSPCAServiceInfo info = (OCSPCAServiceInfo) serviceinfo;	
      data = new HashMap();   
      data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE));

	  data.put(KEYSPEC, info.getKeySpec());
	  data.put(KEYALGORITHM, info.getKeyAlgorithm());
	  setSubjectDN(info.getSubjectDN());
	  setSubjectAltName(info.getSubjectAltName());                       
	  setStatus(serviceinfo.getStatus());
        
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public OCSPCAService(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
      CertTools.installBCProvider();
      loadData(data);  
      if(data.get(OCSPKEYSTORE) != null){    
    	  // lookup keystore passwords      
    	  final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaOcspKeyStorePass(), "ca.ocspkeystorepass");
               
        try {
        	m_log.debug("Loading OCSP keystore");
            KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(OCSPKEYSTORE)).getBytes())),keystorepass.toCharArray());
        	m_log.debug("Finished loading OCSP keystore");
      
            this.ocspsigningkey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
            // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this 
            // Array were of SUNs own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
            // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
            this.ocspcertificatechain =  CertTools.getCertCollectionFromArray(keystore.getCertificateChain(PRIVATESIGNKEYALIAS), null);
            this.info = new OCSPCAServiceInfo(getStatus(),
                                              getSubjectDN(),
                                              getSubjectAltName(), 
                                              (String)data.get(KEYSPEC), 
                                              (String) data.get(KEYALGORITHM),
                                              this.ocspcertificatechain);
      
        } catch (Exception e) {
            throw new IllegalKeyStoreException(e);
        }
        
        data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE));        
     } 
   }
    
    

   /* 
	* @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void init(CA ca) throws Exception {
   	 m_log.debug("OCSPCAService : init ");
   	 // lookup keystore passwords      
   	 final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaOcspKeyStorePass(), "ca.ocspkeystorepass");
   	 // Currently only RSA keys are supported
	 OCSPCAServiceInfo info = (OCSPCAServiceInfo) getExtendedCAServiceInfo();       
                  
	 // Create OSCP KeyStore	    
	 KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
	 keystore.load(null, null);                              
      
	 KeyPair ocspkeys = KeyTools.genKeys(info.getKeySpec(), info.getKeyAlgorithm());
	   	  
	 Certificate ocspcertificate =
	  ca.generateCertificate(new UserDataVO("NOUSERNAME", 	                                          
											info.getSubjectDN(),
											0, 
											info.getSubjectAltName(),
											"NOEMAIL",
											0,0,0,0, null,null,0,0,null)																																
						   , ocspkeys.getPublic(),
						   -1, // KeyUsage
						   ca.getValidity(), 
						   new OCSPSignerCertificateProfile(),
						   null // sequence
						   );
	  
	 ocspcertificatechain = new ArrayList();
	 ocspcertificatechain.add(ocspcertificate);
	 ocspcertificatechain.addAll(ca.getCertificateChain());
	 this.ocspsigningkey = ocspkeys.getPrivate(); 	  	 	  
	  	  	  
     keystore.setKeyEntry(PRIVATESIGNKEYALIAS,ocspkeys.getPrivate(),null,(Certificate[]) ocspcertificatechain.toArray(new Certificate[ocspcertificatechain.size()]));              
     java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
     keystore.store(baos, keystorepass.toCharArray());
     data.put(OCSPKEYSTORE, new String(Base64.encode(baos.toByteArray())));      
     // Store OCSP KeyStore
      
	 setStatus(info.getStatus());
	 this.info = new OCSPCAServiceInfo(info.getStatus(),
									  getSubjectDN(),
									  getSubjectAltName(), 
									  (String)data.get(KEYSPEC), 
									  (String) data.get(KEYALGORITHM),
	                                   ocspcertificatechain);
      
   }   

   /* 
	* @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void update(ExtendedCAServiceInfo serviceinfo, CA ca) throws Exception{		   
   	   OCSPCAServiceInfo info = (OCSPCAServiceInfo) serviceinfo; 
	   m_log.debug("OCSPCAService : update " + serviceinfo.getStatus());
	   setStatus(serviceinfo.getStatus());
   	   if(info.getRenewFlag()){  	 
   	     // Renew The OCSP Signers certificate.	                            	       		 										  
		this.init(ca);
   	   }  
   	    	 
   	   // Only status is updated
	   this.info = new OCSPCAServiceInfo(serviceinfo.getStatus(),
										  getSubjectDN(),
										  getSubjectAltName(), 
										  (String) data.get(KEYSPEC), 
										  (String) data.get(KEYALGORITHM),
	                                      this.ocspcertificatechain);
										         									    	 									  
   }   



	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
        m_log.trace(">extendedService");
        if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive");
			m_log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
        }
        if (!(request instanceof OCSPCAServiceRequest)) {
            throw new IllegalExtendedCAServiceRequestException();            
        }
        OCSPCAServiceRequest ocspServiceReq = (OCSPCAServiceRequest)request;
    	PrivateKey privKey = this.ocspsigningkey;
    	if (ocspServiceReq.getPrivKey() != null) {
        	m_log.debug("Using private key from request");
    		privKey = ocspServiceReq.getPrivKey();
    	}
    	String providerName = ocspServiceReq.getPrivKeyProvider();
        List certChain = ocspcertificatechain;
        if (ocspServiceReq.getCertificateChain() != null) {
        	m_log.debug("Using cert chain from request");
        	certChain = ocspServiceReq.getCertificateChain();
        }        
        ExtendedCAServiceResponse returnval = OCSPUtil.createOCSPCAServiceResponse(ocspServiceReq, privKey, providerName, (X509Certificate[])certChain.toArray(new X509Certificate[0]));
        m_log.trace("<extendedService");		  		
		return returnval;
	}

	
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
		  // New version of the class, upgrade
			String msg = intres.getLocalizedMessage("ocspcaservice.upgrade", new Float(getVersion()));
            m_log.info(msg);
            if(data.get(KEYSPEC) == null) {
            	// Upgrade old rsa keysize to new general keyspec
            	Integer oldKeySize = (Integer)data.get(KEYSIZE);            	
                data.put(KEYSPEC, oldKeySize.toString());
            }            

		  data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}

	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#getExtendedCAServiceInfo()
	 */
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {		
		if(info == null) {
		  info = new OCSPCAServiceInfo(getStatus(),
		                              getSubjectDN(),
		                              getSubjectAltName(), 
		                              (String) data.get(KEYSPEC), 
		                              (String) data.get(KEYALGORITHM),
		                              this.ocspcertificatechain);
		}
		return this.info;
	}
    
	
	public String getSubjectDN(){
		String retval = null;
		String str = (String)data.get(SUBJECTDN);
		 try {
			retval = new String(Base64.decode((str).getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not decode OCSP data from Base64",e);
		} catch (ArrayIndexOutOfBoundsException e) {
			// This is an old CA, where it's not Base64encoded
			m_log.debug("Old non base64 encoded DN: "+str);
			retval = str; 
		}
		
		return retval;		 
	}
    
	public void setSubjectDN(String dn){
		
		 try {
			data.put(SUBJECTDN,new String(Base64.encode(dn.getBytes("UTF-8"),false)));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not encode OCSP data from Base64",e);
		}
	}
	
	public String getSubjectAltName(){
		String retval = null;
		String str= (String) data.get(SUBJECTALTNAME);
		 try {
			retval = new String(Base64.decode((str).getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not decode OCSP data from Base64",e);
		} catch (ArrayIndexOutOfBoundsException e) {
			// This is an old CA, where it's not Base64encoded
			m_log.debug("Old non base64 encoded altname: "+str);
			retval = str; 
		}
		
		return retval;		 
	}
    
	public void setSubjectAltName(String dn){
		
		 try {
			data.put(SUBJECTALTNAME,new String(Base64.encode(dn.getBytes("UTF-8"), false)));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not encode OCSP data from Base64",e);
		}
	}
}

