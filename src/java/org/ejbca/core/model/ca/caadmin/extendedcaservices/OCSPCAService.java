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
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.OCSPException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.certificateprofiles.OCSPSignerCertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.KeyTools;



/** Handles and maintains the CA -part of the OCSP functionality
 * 
 * @version $Id: OCSPCAService.java,v 1.4 2006-06-17 13:08:31 herrvendil Exp $
 */
public class OCSPCAService extends ExtendedCAService implements java.io.Serializable{

    private static Logger m_log = Logger.getLogger(OCSPCAService.class);

    public static final float LATEST_VERSION = 1; 
    
    public static final String SERVICENAME = "OCSPCASERVICE";
    public static final int TYPE = 1; 
      

    private PrivateKey      ocspsigningkey        = null;
    private List            ocspcertificatechain  = null;
    
    private OCSPCAServiceInfo info = null;  
    
    private static final String OCSPKEYSTORE   = "ocspkeystore"; 
    private static final String KEYSIZE        = "keysize";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";
    
	private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";   
    
            
    public OCSPCAService(ExtendedCAServiceInfo serviceinfo)  {
      m_log.debug("OCSPCAService : constructor " + serviceinfo.getStatus()); 	
	  // Currently only RSA keys are supported
	  OCSPCAServiceInfo info = (OCSPCAServiceInfo) serviceinfo;	
      data = new HashMap();   
      data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE));

	  data.put(KEYSIZE, new Integer(info.getKeySize()));
	  data.put(KEYALGORITHM, info.getKeyAlgorithm());
	  setSubjectDN(info.getSubjectDN());
	  setSubjectAltName(info.getSubjectAltName());                       
	  setStatus(serviceinfo.getStatus());
        
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public OCSPCAService(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
      loadData(data);  
      if(data.get(OCSPKEYSTORE) != null){    
         // lookup keystore passwords      
         String keystorepass = null;
         try {
             InitialContext ictx = new InitialContext();
             keystorepass = (String) ictx.lookup("java:comp/env/OCSPKeyStorePass");      
             if (keystorepass == null)
                 throw new IllegalArgumentException("Missing OCSPKeyStorePass property.");
         } catch (NamingException ne) {
             throw new IllegalArgumentException("Missing OCSPKeyStorePass property.");
         }
               
        try {
            KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(OCSPKEYSTORE)).getBytes())),keystorepass.toCharArray());
      
            this.ocspsigningkey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
            this.ocspcertificatechain =  Arrays.asList(keystore.getCertificateChain(PRIVATESIGNKEYALIAS));      
            this.info = new OCSPCAServiceInfo(getStatus(),
                                              getSubjectDN(),
                                              getSubjectAltName(), 
                                              ((Integer) data.get(KEYSIZE)).intValue(), 
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
   public void init(CA ca) throws Exception{
   	 m_log.debug("OCSPCAService : init ");
	 // lookup keystore passwords      
	 InitialContext ictx = new InitialContext();
	 String keystorepass = (String) ictx.lookup("java:comp/env/OCSPKeyStorePass");      
	 if (keystorepass == null)
	   throw new IllegalArgumentException("Missing OCSPKeyPass property.");
        
	  // Currently only RSA keys are supported
	 OCSPCAServiceInfo info = (OCSPCAServiceInfo) getExtendedCAServiceInfo();       
                  
	 // Create OSCP KeyStore	    
	 KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
	 keystore.load(null, null);                              
      
	 KeyPair ocspkeys = KeyTools.genKeys(info.getKeySize());
	   	  
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
						   new OCSPSignerCertificateProfile());
	  
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
									  ((Integer) data.get(KEYSIZE)).intValue(), 
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
										  ((Integer) data.get(KEYSIZE)).intValue(), 
										  (String) data.get(KEYALGORITHM),
	                                      this.ocspcertificatechain);
										         									    	 									  
   }   



	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
        m_log.debug(">extendedService");
        if (!(request instanceof OCSPCAServiceRequest)) {
            throw new IllegalExtendedCAServiceRequestException();            
        }
        if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
            throw new ExtendedCAServiceNotActiveException();                            
        }
        ExtendedCAServiceResponse returnval = null;
        BasicOCSPRespGenerator ocsprespgen = ((OCSPCAServiceRequest)request).getOCSPrespGenerator();
        String sigAlg = ((OCSPCAServiceRequest)request).getSigAlg();
        boolean includeChain = ((OCSPCAServiceRequest)request).includeChain();
        X509Certificate[] chain = null;
        if (includeChain) {
            chain = (X509Certificate[])this.ocspcertificatechain.toArray(new X509Certificate[0]);
        }
        try {
            BasicOCSPResp ocspresp = ocsprespgen.generate(sigAlg, this.ocspsigningkey, chain, new Date(), "BC" );
            returnval = new OCSPCAServiceResponse(ocspresp, chain == null ? null : Arrays.asList(chain));             
        } catch (OCSPException ocspe) {
            throw new ExtendedCAServiceRequestException(ocspe);
        } catch (NoSuchProviderException nspe) {
            throw new ExtendedCAServiceRequestException(nspe);            
        }
        m_log.debug("<extendedService");		  		
		return returnval;
	}

	
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}

	public void upgrade() {
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
		  // New version of the class, upgrade

		  data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}

	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#getExtendedCAServiceInfo()
	 */
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {		
		if(info == null)
		  info = new OCSPCAServiceInfo(getStatus(),
		                              getSubjectDN(),
		                              getSubjectAltName(), 
		                              ((Integer) data.get(KEYSIZE)).intValue(), 
		                              (String) data.get(KEYALGORITHM),
		                              this.ocspcertificatechain);
		
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

