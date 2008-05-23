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

package org.ejbca.core.model.ca.catoken;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;




/**
 * HardCATokenContainer is a class managing the persistent storage of a CA token.
 * 
 *
 * @version $Id$
 */
public class CATokenContainerImpl extends CATokenContainer {

	/**
     * 
     */
    private static final long serialVersionUID = 3363098236866891317L;

    /**
     * @author lars
     *
     */
    private class PropertiesWithHiddenPIN extends Properties {

        /**
         * 
         */
        private static final long serialVersionUID = -2240419700704551683L;
        /**
         * 
         */
        public PropertiesWithHiddenPIN() {
        }
        /**
         * @param defaults
         */
        public PropertiesWithHiddenPIN(Properties defaults) {
            super(defaults);
        }
        public synchronized String toString() {
            int max = size() - 1;
            if (max == -1)
                return "{}";

            final StringBuilder sb = new StringBuilder();
            final Iterator it = entrySet().iterator();

            sb.append('{');
            for (int i = 0; ; i++) {
                final Map.Entry e = (Map.Entry)it.next();
                final String key = (String)e.getKey();
                final String readValue = (String)e.getValue();
                final String value = readValue!=null && readValue.length()>0 && key.trim().equalsIgnoreCase(ICAToken.AUTOACTIVATE_PIN_PROPERTY) ? "xxxx" : readValue;
                sb.append(key);
                sb.append('=');
                sb.append(value);

                if (i == max)
                    return sb.append('}').toString();
                sb.append(", ");
            }
        }

    }
    /** Log4j instance */
	private static final Logger log = Logger.getLogger(CATokenContainerImpl.class);
	
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	private ICAToken catoken = null; 

	public static final float LATEST_VERSION = 5;


	// Default Values

	protected static final String CLASSPATH                       = "classpath";   
	protected static final String PROPERTYDATA                 = "propertydata";

	/**
	 * 
	 * @param tokentype CATokenInfo.CATOKENTYPE_HSM or similar
	 */
	public CATokenContainerImpl(CATokenInfo catokeninfo){
		super();
		updateCATokenInfo(catokeninfo);
	}

	public CATokenContainerImpl(HashMap data) {
		loadData(data);  
	}

	// Public Methods    

	/**
	 * Returns the current hardcatoken configuration.
	 */
	public CATokenInfo getCATokenInfo() {
		// First make a call to get the CAToken, so we initialize it
		getCAToken();
		CATokenInfo info = null;
		if (catoken instanceof NullCAToken) {
			info = new NullCATokenInfo();
		}
		String classpath = getClassPath();
		if (catoken instanceof SoftCAToken) {
			SoftCATokenInfo sinfo = new SoftCATokenInfo();
			sinfo.setSignKeySpec((String) data.get(SIGNKEYSPEC));
			sinfo.setSignKeyAlgorithm((String) data.get(SIGNKEYALGORITHM));  
			sinfo.setEncKeySpec((String) data.get(ENCKEYSPEC));
			sinfo.setEncKeyAlgorithm((String) data.get(ENCKEYALGORITHM));  
			sinfo.setEncryptionAlgorithm((String) data.get(ENCRYPTIONALGORITHM));
			if (StringUtils.isEmpty(classpath)) {
				classpath = SoftCAToken.class.getName(); 
			}
			sinfo.setClassPath(classpath);
			info = sinfo;
		} else if (catoken instanceof NullCAToken) {
			NullCATokenInfo ninfo = new NullCATokenInfo();
			info = ninfo;
		} else {
			HardCATokenInfo hinfo = new HardCATokenInfo();
			info = hinfo;
		}		
		info.setClassPath(getClassPath());
		info.setProperties(getPropertyData());
		info.setSignatureAlgorithm(getSignatureAlgorithm());

		// Set status of the CA token
		int status = ICAToken.STATUS_OFFLINE;
		if ( catoken != null ){
			status = catoken.getCATokenStatus();
		}
		log.debug("Setting CATokenInfo.status to: "+status);
		info.setCATokenStatus(status);

		return info;
	}

	/**
	 *  Returns the type of CA token, from CATokenConstants.
	 *  @return integer one of CATokenConstants.CATOKENTYPE_XXX, or 0 if we don't know the type
	 *  @see CATokenConstants.CATOKENTYPE_XXX
	 */
	public int getCATokenType() {
		int ret = 0;
		if (data.get(CATOKENTYPE) != null) {
        	ret = (Integer)(data.get(CATOKENTYPE));
		}
		return ret;
	}

	/** 
	 * Updates the hardcatoken configuration
	 */
	public void updateCATokenInfo(CATokenInfo catokeninfo) {

		boolean changed = false;
		// We must be able to upgrade class path
		if (catokeninfo.getClassPath() != null) {
			this.setClassPath(catokeninfo.getClassPath());			
			this.catoken = null;
		}
		if(getSignatureAlgorithm() == null) {
			this.setSignatureAlgorithm(catokeninfo.getSignatureAlgorithm());			
		}

		String props = this.getPropertyData();
		String newprops = catokeninfo.getProperties();
		if ( (newprops != null) && !StringUtils.equals(props, newprops)) {
			this.setPropertyData(newprops);				
			changed = true;
		}			

		if (catokeninfo instanceof NullCATokenInfo) {
			log.debug("CA Token is CATOKENTYPE_NULL");
			if (data.get(CATOKENTYPE) == null) {
		    	data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_NULL));
				changed = true;				
			}
		}

		if (catokeninfo instanceof HardCATokenInfo) {
			log.debug("CA Token is CATOKENTYPE_HSM");
			if (data.get(CATOKENTYPE) == null) {
				data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_HSM));
				changed = true;
			}
		}

		if (catokeninfo instanceof SoftCATokenInfo) {
			log.debug("CA Token is CATOKENTYPE_P12");
			if (data.get(CATOKENTYPE) == null) {
				data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_P12));
				changed = true;
			}
			SoftCATokenInfo sinfo = (SoftCATokenInfo) catokeninfo;
			// Below for soft CA tokens
			String str = sinfo.getSignKeySpec();
			if ( (str != null) && !StringUtils.equals((String)data.get(SIGNKEYSPEC), str)) {
				data.put(SIGNKEYSPEC, str);
				changed = true;
			}
			str = sinfo.getSignKeyAlgorithm();
			if ( (str != null) && !StringUtils.equals((String)data.get(SIGNKEYALGORITHM), str)) {
				data.put(SIGNKEYALGORITHM, str);
				changed = true;
			}
			str = sinfo.getEncKeySpec();
			if ( (str != null) && !StringUtils.equals((String)data.get(ENCKEYSPEC), str)) {
				data.put(ENCKEYSPEC, str);
				changed = true;
			}
			str = sinfo.getEncKeyAlgorithm();
			if ( (str != null) && !StringUtils.equals((String)data.get(ENCKEYALGORITHM), str)) {
				data.put(ENCKEYALGORITHM, str);
				changed = true;
			}
			str = sinfo.getEncryptionAlgorithm();
			if ( (str != null) && !StringUtils.equals((String)data.get(ENCRYPTIONALGORITHM), str)) {
				data.put(ENCRYPTIONALGORITHM, str);
				changed = true;
			}
		}
		if (changed) {
			this.catoken = null;
		}

	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#activate(java.lang.String)
	 */
	public void activate(String authorizationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		getCAToken().activate(authorizationcode);		
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#deactivate()
	 */
	public boolean deactivate() {		
		return getCAToken().deactivate();
	}


	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#getPrivateKey()
	 */
	public PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException{		
		return getCAToken().getPrivateKey(purpose);
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#getPublicKey()
	 */
	public PublicKey getPublicKey(int purpose) throws CATokenOfflineException{
		return getCAToken().getPublicKey(purpose);
	}


	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#getProvider()
	 */
	public String getProvider() {		
		return getCAToken().getProvider();
	}
	public String getJCEProvider() {		
		return getCAToken().getJCEProvider();
	}

	/**
	 * Method that generates the keys that will be used by the CAToken.
	 * Only available for Soft CA Tokens so far.
	 * 
	 * @param authenticationCode the password used to encrypt the keystore, laterneeded to activate CA Token
	 * @param renew flag indicating if the keys are renewed instead of created fresh. Renewing keys does not 
	 * create new encryption keys, since this would make it impossible to decrypt old stuff.
	 */
	public void generateKeys(String authenticationCode, boolean renew) throws Exception{  
		log.debug(">generateKeys");
		CATokenInfo catokeninfo = getCATokenInfo();
		if ( !(catokeninfo instanceof SoftCATokenInfo) ) {
			log.error("generateKeys is only available for Soft CA tokens (PKCS12)");
			return;
		}
		
		// Currently only RSA keys are supported
		SoftCATokenInfo info = (SoftCATokenInfo) catokeninfo;       
		KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		keystore.load(null, null);

		// Generate signature keys.
		KeyPair signkeys = KeyTools.genKeys(info.getSignKeySpec(), info.getSignKeyAlgorithm());
		// generate dummy certificate
		Certificate[] certchain = new Certificate[1];
		certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, signkeys.getPrivate(), signkeys.getPublic(), info.getSignatureAlgorithm(), true);

		keystore.setKeyEntry(SoftCAToken.PRIVATESIGNKEYALIAS,signkeys.getPrivate(),null, certchain);             

		PublicKey pubEnc = null;
		PrivateKey privEnc = null;
		if (!renew) {
			// Generate encryption keys.  
			// Encryption keys must be RSA still
			KeyPair enckeys = KeyTools.genKeys(info.getEncKeySpec(), info.getEncKeyAlgorithm());
			pubEnc = enckeys.getPublic();
			privEnc = enckeys.getPrivate();
		} else {
			// Get the already existing keys
			ICAToken token = getCAToken();
			pubEnc = token.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
			privEnc = token.getPrivateKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
			
		}
		// generate dummy certificate
		certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, privEnc, pubEnc, info.getEncryptionAlgorithm(), true);
		keystore.setKeyEntry(SoftCAToken.PRIVATEDECKEYALIAS, privEnc, null, certchain);			
		
		// Store the key store
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		keystore.store(baos, authenticationCode.toCharArray());
		data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));
		data.put(SIGNKEYSPEC, info.getSignKeySpec());
		data.put(SIGNKEYALGORITHM, info.getSignKeyAlgorithm());
		data.put(SIGNATUREALGORITHM, info.getSignatureAlgorithm());
		data.put(ENCKEYSPEC, info.getEncKeySpec());
		data.put(ENCKEYALGORITHM, info.getEncKeyAlgorithm());
		data.put(ENCRYPTIONALGORITHM, info.getEncryptionAlgorithm());
		
		// Finally reset the token so it will be re-read when we want to use it
		this.catoken = null;
		log.debug("<generateKeys");
	}

	/**
	 * Method that import CA token keys from a P12 file. Was originally used when upgrading from 
	 * old EJBCA versions. Only supports SHA1 and SHA256 with RSA or ECDSA.
	 */
	public void importKeys(String authenticationCode, PrivateKey privatekey, PublicKey publickey, PrivateKey privateEncryptionKey,
			PublicKey publicEncryptionKey, Certificate[] caSignatureCertChain) throws Exception{


		// Currently only RSA keys are supported
		KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
		keystore.load(null,null);

		// Assume that the same hash algorithm is used for signing that was used to sign this CA cert
		String signatureAlgorithm = CertTools.getSignatureAlgorithm(caSignatureCertChain[0]);
		String keyAlg = null;
		if ( publickey instanceof RSAPublicKey ) {
			keyAlg  = CATokenInfo.KEYALGORITHM_RSA;
		} else {
			keyAlg = CATokenInfo.KEYALGORITHM_ECDSA;
		}

		// import sign keys.
		String keyspec = null;
		if ( publickey instanceof RSAPublicKey ) {
			keyspec = Integer.toString( ((RSAPublicKey) publickey).getModulus().bitLength() );
			log.debug("KeySize="+keyspec);
		} else {
			Enumeration en = ECNamedCurveTable.getNames();
			while ( en.hasMoreElements() ) {
				String currentCurveName = (String) en.nextElement();
				if ( (ECNamedCurveTable.getParameterSpec(currentCurveName)).getCurve().equals( ((ECPrivateKey) privatekey).getParameters().getCurve() ) ) {
					keyspec = currentCurveName;
					break;
				}
			}

			if ( keyspec==null ) {
				keyspec = "unknown";
			}
			privatekey = (ECPrivateKey) privatekey;
			publickey = (ECPublicKey) publickey;
			log.debug("ECName="+keyspec);
		}
		Certificate[] certchain = new Certificate[1];
		certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, privatekey, publickey, signatureAlgorithm, true);
		
		keystore.setKeyEntry(SoftCAToken.PRIVATESIGNKEYALIAS, privatekey, null, certchain);       
		data.put(SIGNKEYSPEC, keyspec);
		data.put(SIGNKEYALGORITHM, keyAlg);
		data.put(SIGNATUREALGORITHM, signatureAlgorithm);

		// generate enc keys.  
		// Encryption keys must be RSA still
		String encryptionSignatureAlgorithm = signatureAlgorithm;
		keyAlg = CATokenInfo.KEYALGORITHM_RSA;
		keyspec = "2048";
		if ( signatureAlgorithm.equals(CATokenInfo.SIGALG_SHA256_WITH_ECDSA) ) {
			encryptionSignatureAlgorithm = CATokenInfo.SIGALG_SHA256_WITH_RSA;
		} else if ( signatureAlgorithm.equals(CATokenInfo.SIGALG_SHA1_WITH_ECDSA) ) {
			encryptionSignatureAlgorithm = CATokenInfo.SIGALG_SHA1_WITH_RSA;
		}
		KeyPair enckeys = null;
		if ( publicEncryptionKey == null ||  privateEncryptionKey == null ) {
			enckeys = KeyTools.genKeys(keyspec, keyAlg);
		}
		else {
			enckeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
		}
		// generate dummy certificate
		certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, enckeys.getPrivate(), enckeys.getPublic(), encryptionSignatureAlgorithm, true);
		keystore.setKeyEntry(SoftCAToken.PRIVATEDECKEYALIAS,enckeys.getPrivate(),null,certchain);              

		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		keystore.store(baos, authenticationCode.toCharArray());
		data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));
		data.put(ENCKEYSPEC, keyspec);
		data.put(ENCKEYALGORITHM, keyAlg);
		data.put(ENCRYPTIONALGORITHM, encryptionSignatureAlgorithm);
		
		// Finally reset the token so it will be re-read when we want to use it
		this.catoken = null;
	}

	//
	// Private methods
	//
	/**
	 *  Returns the class path of a CA Token.
	 */    
	private String getClassPath(){
		return (String) data.get(CLASSPATH);
	}

	/**
	 *  Sets the class path of a CA Token.
	 */        
	private void setClassPath(String classpath){
		data.put(CLASSPATH, classpath);	
	}

	/**
	 *  Returns the SignatureAlgoritm
	 */    
	private String getSignatureAlgorithm(){
		return (String) data.get(SIGNATUREALGORITHM);
	}

	/**
	 *  Sets the SignatureAlgoritm
	 */        
	private void setSignatureAlgorithm(String signaturealgoritm){
		data.put(SIGNATUREALGORITHM, signaturealgoritm);	
	}


	/**
	 *  Returns the propertydata used to configure this CA Token.
	 */    
	private String getPropertyData(){
		return (String) data.get(PROPERTYDATA);
	}

	/**
	 *  Sets the propertydata used to configure this CA Token.
	 */   
	private void setPropertyData(String propertydata){
		data.put(PROPERTYDATA, propertydata);	
	}

	private Properties getProperties() throws IOException{
		Properties prop = new PropertiesWithHiddenPIN();
		String pdata = getPropertyData();
		if (pdata != null) {
			prop.load(new ByteArrayInputStream(pdata.getBytes()));			
		}
		return prop;
	}



	private ICAToken getCAToken() {
		if(catoken == null){
			try{				
				Class implClass = Class.forName( getClassPath());
				Object obj = implClass.newInstance();
				this.catoken = (ICAToken) obj;
				this.catoken.init(getProperties(), data, getSignatureAlgorithm());				
			}catch(Throwable e){
				log.error("Error contructing CA Token: ", e);
			}
		}

		return catoken;
	}

	//
	// Methods for implementing the UpgradeableDataHashMap
	//

	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}



	public void upgrade() {
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
			String msg = intres.getLocalizedMessage("catoken.upgrade", new Float(getVersion()));
			log.info(msg);
			if(data.get(SIGNKEYALGORITHM) == null) {
				String oldKeyAlg = (String)data.get(KEYALGORITHM); 
				if (oldKeyAlg != null) {
					data.put(SIGNKEYALGORITHM, oldKeyAlg);
					data.put(ENCKEYALGORITHM, oldKeyAlg);					
				}
			}            
			if(data.get(SIGNKEYSPEC) == null) {
				Integer oldKeySize = ((Integer) data.get(KEYSIZE));
				if (oldKeySize != null) {
					data.put(SIGNKEYSPEC, oldKeySize.toString());
					data.put(ENCKEYSPEC, oldKeySize.toString());					
				}
			}
			if(data.get(ENCRYPTIONALGORITHM) == null) {
				String signAlg = (String)data.get(SIGNATUREALGORITHM);            	
				data.put(ENCRYPTIONALGORITHM, signAlg);
			}
			if (data.get(CLASSPATH) == null) {
				String classpath = SoftCAToken.class.getName();
				if (data.get(KEYSTORE) == null) {
					classpath = NullCAToken.class.getName();
				}
				log.info("Adding new classpath to CA Token data: "+classpath);
				data.put(CLASSPATH, classpath);
			}

			data.put(VERSION, new Float(LATEST_VERSION));
		}  		
	}


}
