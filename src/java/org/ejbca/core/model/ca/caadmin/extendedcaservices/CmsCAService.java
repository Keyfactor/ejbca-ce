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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.certificateprofiles.XKMSCertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;



/** Handles and maintains the CA-part of the CMS message functionality.
 *  The service have it's own certificate used for signing and encryption 
 * 
 * @version $Id: CmsCAService.java,v 1.1 2006-12-27 11:13:56 anatom Exp $
 */
public class CmsCAService extends ExtendedCAService implements java.io.Serializable{

	private static Logger m_log = Logger.getLogger(CmsCAService.class);
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	public static final float LATEST_VERSION = 1; 

	public static final String SERVICENAME = "CMSCASERVICE";          

	private PrivateKey      privKey        = null;
	private List            certificatechain  = null;

	private CmsCAServiceInfo info = null;  

	private static final String KEYSTORE       = "keystore"; 
	private static final String KEYSPEC        = "keyspec";
	private static final String KEYALGORITHM   = "keyalgorithm";
	private static final String SUBJECTDN      = "subjectdn";
	private static final String SUBJECTALTNAME = "subjectaltname";

	private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";   



	public CmsCAService(ExtendedCAServiceInfo serviceinfo)  {
		m_log.debug("CmsCAService : constructor " + serviceinfo.getStatus()); 
		CertTools.installBCProvider();
		// Currently only RSA keys are supported
		CmsCAServiceInfo info = (CmsCAServiceInfo) serviceinfo;	
		data = new HashMap();   
		data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE));

		data.put(KEYSPEC, info.getKeySpec());
		data.put(KEYALGORITHM, info.getKeyAlgorithm());
		setSubjectDN(info.getSubjectDN());
		setSubjectAltName(info.getSubjectAltName());                       
		setStatus(serviceinfo.getStatus());

		data.put(VERSION, new Float(LATEST_VERSION));
	}

	public CmsCAService(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
		CertTools.installBCProvider();
		loadData(data);  
		if(data.get(KEYSTORE) != null){    
			// lookup keystore passwords      
			String keystorepass = ServiceLocator.getInstance().getString("java:comp/env/CMSKeyStorePass");      
			if (keystorepass == null)
				throw new IllegalArgumentException("Missing CMSKeyStorePass property.");

			try {
				m_log.debug("Loading keystore");
				KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
				keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(KEYSTORE)).getBytes())),keystorepass.toCharArray());
				m_log.debug("Finished loading keystore");

				this.privKey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
				this.certificatechain =  Arrays.asList(keystore.getCertificateChain(PRIVATESIGNKEYALIAS));      
				this.info = new CmsCAServiceInfo(getStatus(),
						getSubjectDN(),
						getSubjectAltName(), 
						(String)data.get(KEYSPEC), 
						(String) data.get(KEYALGORITHM),
						this.certificatechain);

			} catch (Exception e) {
				throw new IllegalKeyStoreException(e);
			}

			data.put(EXTENDEDCASERVICETYPE, new Integer(ExtendedCAServiceInfo.TYPE_CMSEXTENDEDSERVICE));        
		} 
	}



	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */   
	public void init(CA ca) throws Exception {
		m_log.debug("CmsCAService : init");
		// lookup keystore passwords      
		String keystorepass = ServiceLocator.getInstance().getString("java:comp/env/CMSKeyStorePass");      
		if (keystorepass == null)
			throw new IllegalArgumentException("Missing CMSKeyStorePass property.");

		// Currently only RSA keys are supported
		CmsCAServiceInfo info = (CmsCAServiceInfo) getExtendedCAServiceInfo();       

		// Create KeyStore	    
		KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		keystore.load(null, null);                              

		KeyPair cmskeys = KeyTools.genKeys(info.getKeySpec(), info.getKeyAlgorithm());

		Certificate certificate =
			ca.generateCertificate(new UserDataVO("NOUSERNAME", 	                                          
					info.getSubjectDN(),
					0, 
					info.getSubjectAltName(),
					"NOEMAIL",
					0,0,0,0, null,null,0,0,null)																																
			, cmskeys.getPublic(),
			-1, // KeyUsage
			ca.getValidity(),
			new XKMSCertificateProfile()); // We can use the (simple) XKMS profile, since it uses the same values as we want for CMS

		certificatechain = new ArrayList();
		certificatechain.add(certificate);
		certificatechain.addAll(ca.getCertificateChain());
		this.privKey = cmskeys.getPrivate(); 	  	 	  

		keystore.setKeyEntry(PRIVATESIGNKEYALIAS,cmskeys.getPrivate(),null,(Certificate[]) certificatechain.toArray(new Certificate[certificatechain.size()]));              
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		keystore.store(baos, keystorepass.toCharArray());
		data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));      
		// Store KeyStore

		setStatus(info.getStatus());
		this.info = new CmsCAServiceInfo(info.getStatus(),
				getSubjectDN(),
				getSubjectAltName(), 
				(String)data.get(KEYSPEC), 
				(String) data.get(KEYALGORITHM),
				certificatechain);
	}   

	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */   
	public void update(ExtendedCAServiceInfo serviceinfo, CA ca) throws Exception{		   
		CmsCAServiceInfo info = (CmsCAServiceInfo) serviceinfo; 
		m_log.debug("CmsCAService : update " + serviceinfo.getStatus());
		setStatus(serviceinfo.getStatus());
		if(info.getRenewFlag()){  	 
			// Renew The Signers certificate.	                            	       		 										  
			this.init(ca);
		}  

		// Only status is updated
		this.info = new CmsCAServiceInfo(serviceinfo.getStatus(),
				getSubjectDN(),
				getSubjectAltName(), 
				(String) data.get(KEYSPEC), 
				(String) data.get(KEYALGORITHM),
				certificatechain);							         									    	 									  
	}   



	/* 
	 * @see org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAService#extendedService(org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest)
	 */
	public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException,ExtendedCAServiceNotActiveException {
		m_log.debug(">extendedService");
		if (!(request instanceof CmsCAServiceRequest)) {
			throw new IllegalExtendedCAServiceRequestException();            
		}
		if (this.getStatus() != ExtendedCAServiceInfo.STATUS_ACTIVE) {
			String msg = intres.getLocalizedMessage("caservice.notactive");
			m_log.error(msg);
			throw new ExtendedCAServiceNotActiveException(msg);                            
		}
		ExtendedCAServiceResponse returnval = null;
		X509Certificate signerCert = (X509Certificate) certificatechain.get(0);
		CmsCAServiceRequest serviceReq = (CmsCAServiceRequest)request;

		// TODO 

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
		if(info == null){
			info = new CmsCAServiceInfo(getStatus(),
					getSubjectDN(),
					getSubjectAltName(), 
					(String) data.get(KEYSPEC), 
					(String) data.get(KEYALGORITHM),
					certificatechain);
		}

		return this.info;
	}


	public String getSubjectDN(){
		String retval = null;
		String str = (String)data.get(SUBJECTDN);
		try {
			retval = new String(Base64.decode((str).getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not decode data from Base64",e);
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
			m_log.error("Could not encode data from Base64",e);
		}
	}

	public String getSubjectAltName(){
		String retval = null;
		String str= (String) data.get(SUBJECTALTNAME);
		try {
			retval = new String(Base64.decode((str).getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			m_log.error("Could not decode data from Base64",e);
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
			m_log.error("Could not encode data from Base64",e);
		}
	}
}

