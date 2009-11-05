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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.certificateprofiles.XKMSCertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;
import org.w3c.dom.Document;



/** Handles and maintains the CA-part of the XKMS functionality.
 *  The service have it's own certificate used for signing and encryption 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class XKMSCAService extends ExtendedCAService implements java.io.Serializable{

    private static Logger m_log = Logger.getLogger(XKMSCAService.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final float LATEST_VERSION = 1; 
    
    public static final String SERVICENAME = "XKMSCASERVICE";          

    private PrivateKey      xKMSkey        = null;
    private List            xKMScertificatechain  = null;
    
    private XKMSCAServiceInfo info = null;  
    
    private static final String XKMSKEYSTORE   = "xkmskeystore"; 
    private static final String KEYSPEC        = "keyspec";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";
    
	private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";   


            
    public XKMSCAService(ExtendedCAServiceInfo serviceinfo)  {
      m_log.debug("XKMSCAService : constructor " + serviceinfo.getStatus()); 
      CertTools.installBCProvider();
	  // Currently only RSA keys are supported
      XKMSCAServiceInfo info = (XKMSCAServiceInfo) serviceinfo;	
      data = new HashMap();   
      data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE));

	  data.put(KEYSPEC, info.getKeySpec());
	  data.put(KEYALGORITHM, info.getKeyAlgorithm());
	  setSubjectDN(info.getSubjectDN());
	  setSubjectAltName(info.getSubjectAltName());                       
	  setStatus(serviceinfo.getStatus());
        
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public XKMSCAService(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
      CertTools.installBCProvider();
      loadData(data);  
      if(data.get(XKMSKEYSTORE) != null){    
    	  // lookup keystore passwords
    	  final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaXkmsKeyStorePass(), "ca.xkmskeystorepass");
               
        try {
        	m_log.debug("Loading XKMS keystore");
            KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(XKMSKEYSTORE)).getBytes())),keystorepass.toCharArray());
        	m_log.debug("Finished loading XKMS keystore");
      
            this.xKMSkey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
            // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this 
            // Array were of SUNs own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
            // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
            this.xKMScertificatechain =  CertTools.getCertCollectionFromArray(keystore.getCertificateChain(PRIVATESIGNKEYALIAS), null);
            this.info = new XKMSCAServiceInfo(getStatus(),
                                              getSubjectDN(),
                                              getSubjectAltName(), 
                                              (String)data.get(KEYSPEC), 
                                              (String) data.get(KEYALGORITHM),
                                              this.xKMScertificatechain);
      
        } catch (Exception e) {
            throw new IllegalKeyStoreException(e);
        }
        
        data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_XKMSEXTENDEDSERVICE));        
     } 
   }
    
    

   /* 
	* @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void init(CA ca) throws Exception {
   	 m_log.trace(">init");
	 // lookup keystore passwords      
   	 final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaXkmsKeyStorePass(), "ca.xkmskeystorepass");
   	 // Currently only RSA keys are supported
	 XKMSCAServiceInfo info = (XKMSCAServiceInfo) getExtendedCAServiceInfo();       
                  
	 // Create XKMS KeyStore	    
	 KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
	 keystore.load(null, null);                              
      
	 KeyPair xKMSkeys = KeyTools.genKeys(info.getKeySpec(), info.getKeyAlgorithm());
	   	  
	 UserDataVO user = new UserDataVO("NOUSERNAME", 	                                          
				info.getSubjectDN(),
				0, 
				info.getSubjectAltName(),
				"NOEMAIL",
				0,0,0,0, null,null,0,0,null);
	 Certificate xKMSCertificate = ca.generateCertificate(
			 user																																
			,xKMSkeys.getPublic(),
			-1, // KeyUsage
			ca.getValidity(), 
			new XKMSCertificateProfile(),
			null // sequence
			);
	  
	 xKMScertificatechain = new ArrayList();
	 xKMScertificatechain.add(xKMSCertificate);
	 xKMScertificatechain.addAll(ca.getCertificateChain());
	 this.xKMSkey = xKMSkeys.getPrivate(); 	  	 	  
	  	  	  
     keystore.setKeyEntry(PRIVATESIGNKEYALIAS,xKMSkeys.getPrivate(),null,(Certificate[]) xKMScertificatechain.toArray(new Certificate[xKMScertificatechain.size()]));              
     java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
     keystore.store(baos, keystorepass.toCharArray());
     data.put(XKMSKEYSTORE, new String(Base64.encode(baos.toByteArray())));      
     // Store XKMS KeyStore
      
	 setStatus(info.getStatus());
	 this.info = new XKMSCAServiceInfo(info.getStatus(),
									  getSubjectDN(),
									  getSubjectAltName(), 
									  (String)data.get(KEYSPEC), 
									  (String) data.get(KEYALGORITHM),
	                                  xKMScertificatechain);
   	 m_log.trace("<init");
   }   

   /* 
	* @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	*/   
   public void update(ExtendedCAServiceInfo serviceinfo, CA ca) throws Exception{		   
   	   XKMSCAServiceInfo info = (XKMSCAServiceInfo) serviceinfo; 
	   m_log.trace(">update: " + serviceinfo.getStatus());
	   setStatus(serviceinfo.getStatus());
   	   if(info.getRenewFlag()){  	 
   	     // Renew The XKMS Signers certificate.	                            	       		 										  
		this.init(ca);
   	   }  
   	    	 
   	   // Only status is updated
	   this.info = new XKMSCAServiceInfo(serviceinfo.getStatus(),
										  getSubjectDN(),
										  getSubjectAltName(), 
										  (String) data.get(KEYSPEC), 
										  (String) data.get(KEYALGORITHM),
	                                      xKMScertificatechain);										         									    	 									  
	   m_log.trace("<update: " + serviceinfo.getStatus());
   }   



	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
        m_log.trace(">extendedService");
        if (!(request instanceof XKMSCAServiceRequest)) {
            throw new IllegalExtendedCAServiceRequestException();            
        }
        if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive");
			m_log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
        }
        ExtendedCAServiceResponse returnval = null;
    	X509Certificate signerCert = (X509Certificate) xKMScertificatechain.get(0);
        XKMSCAServiceRequest xKMSServiceReq = (XKMSCAServiceRequest)request;
        
        Document doc = xKMSServiceReq.getDoc();
        if(xKMSServiceReq.isSign()){
        	try{

				org.apache.xml.security.signature.XMLSignature xmlSig = new org.apache.xml.security.signature.XMLSignature(doc, "", org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
				org.apache.xml.security.transforms.Transforms transforms = new org.apache.xml.security.transforms.Transforms(doc);
				transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
				transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
				xmlSig.addDocument("#" + xKMSServiceReq.getId(), transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);        			
				xmlSig.addKeyInfo(signerCert);
				doc.getDocumentElement().insertBefore( xmlSig.getElement() ,doc.getDocumentElement().getFirstChild());
				xmlSig.sign(xKMSkey);               		
        		
        		returnval = new XKMSCAServiceResponse(doc);
        	}catch (XMLSignatureException e) {
        		throw new ExtendedCAServiceRequestException(e);
			} catch (XMLSecurityException e) {
				throw new ExtendedCAServiceRequestException(e);
			}
        }
        
        m_log.trace("<extendedService");		  		
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
		if(info == null){
		  info = new XKMSCAServiceInfo(getStatus(),
		                              getSubjectDN(),
		                              getSubjectAltName(), 
		                              (String) data.get(KEYSPEC), 
		                              (String) data.get(KEYALGORITHM),
		                              xKMScertificatechain);
		}
		
		return this.info;
	}
    
	
	public String getSubjectDN(){
		String retval = null;
		String str = (String)data.get(SUBJECTDN);
		 try {
			retval = new String(Base64.decode((str).getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not decode XKMS data from Base64",e);
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
			m_log.error("Could not encode XKMS data from Base64",e);
		}
	}
	
	public String getSubjectAltName(){
		String retval = null;
		String str= (String) data.get(SUBJECTALTNAME);
		 try {
			retval = new String(Base64.decode((str).getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not decode XKMS data from Base64",e);
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
			m_log.error("Could not encode XKMS data from Base64",e);
		}
	}
}

