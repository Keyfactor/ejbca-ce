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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
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



/** Handles and maintains the CA-part of the CMS message functionality.
 *  The service have it's own certificate used for signing and encryption 
 * 
 * @version $Id$
 */
public class CmsCAService extends ExtendedCAService implements java.io.Serializable{

    /** Determines if a de-serialized file is compatible with this class.
    *
    * Maintainers must change this value if and only if the new version
    * of this class is not compatible with old versions. See Sun docs
    * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
    * /serialization/spec/version.doc.html> details. </a>
    */
	private static final long serialVersionUID = 5273836489592921586L;
	
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
		    final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaCmsKeyStorePass(), "ca.cmskeystorepass");

			try {
				m_log.debug("Loading CMS keystore");
				KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
				keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(KEYSTORE)).getBytes())),keystorepass.toCharArray());
				m_log.debug("Finished loading CMS keystore");

				this.privKey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
	            // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this 
	            // Array were of SUNs own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
	            // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
	            this.certificatechain =  CertTools.getCertCollectionFromArray(keystore.getCertificateChain(PRIVATESIGNKEYALIAS), null);
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
	    final String keystorepass = StringTools.passwordDecryption(EjbcaConfiguration.getCaCmsKeyStorePass(), "ca.cmskeystorepass");
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
			new XKMSCertificateProfile(), // We can use the (simple) XKMS profile, since it uses the same values as we want for CMS
			null // sequence
			);

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
		m_log.trace(">extendedService");
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

        // Create the signed data
        CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();
        try {
        	byte[] resp = serviceReq.getDoc();
            // Add our signer info and sign the message
        	if((serviceReq.getMode() & CmsCAServiceRequest.MODE_SIGN) != 0){
        		CertStore certs;
        		certs = CertStore.getInstance("Collection",
        				new CollectionCertStoreParameters(certificatechain), "BC");
        		gen1.addCertificatesAndCRLs(certs);
        		gen1.addSigner(privKey, signerCert, CMSSignedGenerator.DIGEST_SHA1);
        		CMSProcessable msg = new CMSProcessableByteArray(resp);
        		CMSSignedData s = gen1.generate(msg, true, "BC");
        		resp = s.getEncoded();
        	}
        	if((serviceReq.getMode() & CmsCAServiceRequest.MODE_ENCRYPT) != 0){
    	        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
    	        edGen.addKeyTransRecipient(getCMSCertificate());	
    	        CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(resp),CMSEnvelopedDataGenerator.DES_EDE3_CBC,"BC");
    	        resp = ed.getEncoded();
        	}
        	if((serviceReq.getMode() & CmsCAServiceRequest.MODE_DECRYPT) != 0){
	            CMSEnvelopedData ed = new CMSEnvelopedData(resp);   	    	
	            RecipientInformationStore  recipients = ed.getRecipientInfos(); 
	            RecipientId id = new RecipientId();
	            id.setIssuer(getCMSCertificate().getIssuerX500Principal());
	            id.setSerialNumber(getCMSCertificate().getSerialNumber());
	            RecipientInformation recipient = recipients.get(id); 
	            if(recipient != null){
	                resp = recipient.getContent(this.privKey, "BC");
	            }
        	}
        	returnval = new CmsCAServiceResponse(resp);
        } catch (InvalidAlgorithmParameterException e) {
        	m_log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
        } catch (NoSuchAlgorithmException e) {
        	m_log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
        } catch (NoSuchProviderException e) {
        	m_log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
        } catch (CertStoreException e) {
        	m_log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
		} catch (CMSException e) {
        	m_log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
		} catch (IOException e) {
        	m_log.error("Error in CmsCAService", e);
        	throw new ExtendedCAServiceRequestException(e);
		}

		m_log.trace("<extendedService");		  		
		return returnval;
	}

    private X509Certificate cmsCertificate = null;
	private X509Certificate getCMSCertificate() {
		if(cmsCertificate == null){
			Iterator iter = certificatechain.iterator();
			while(iter.hasNext()){
				X509Certificate cert = (X509Certificate) iter.next();
				if(cert.getBasicConstraints() == -1){
					cmsCertificate = cert;
					break;
				}
			}
		}
		return cmsCertificate;
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

