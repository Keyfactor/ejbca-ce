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

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;

import javax.naming.InitialContext;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: SoftCAToken.java,v 1.9 2007-04-02 08:26:35 jeklund Exp $
 */
public class SoftCAToken extends CAToken implements java.io.Serializable{

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SoftCAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** When upgradeing this version, you must up the version of the CA as well, 
     * otherwise the upgraded CA token will not be stored in the database.
     */
    public static final float LATEST_VERSION = 3; 
    
    private static final String  PROVIDER = "BC";

    private PrivateKey privateSignKey = null;
    private PrivateKey privateDecKey  = null;
    private PublicKey  publicSignKey  = null;
    private PublicKey  publicEncKey   = null;
    private Certificate encCert = null;
    
    private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";
    private static final String PRIVATEDECKEYALIAS = "privatedeckeyalias";
    
    protected static final String SIGNKEYSPEC       = "SIGNKEYSPEC";
    protected static final String ENCKEYSPEC        = "ENCKEYSPEC";
    protected static final String SIGNKEYALGORITHM  = "SIGNKEYALGORITHM";
    protected static final String ENCKEYALGORITHM   = "ENCKEYALGORITHM";
    protected static final String KEYSTORE          = "KEYSTORE";

    /** Old provided for upgrade purposes from 3.3. -> 3.4 */
    protected static final String KEYALGORITHM  = "KEYALGORITHM";
    /** Old provided for upgrade purposes from 3.3. -> 3.4 */
    protected static final String KEYSIZE       = "KEYSIZE";

    public SoftCAToken(){
      data = new HashMap();   
      data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_P12));
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public SoftCAToken(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
      loadData(data);  
      if(data.get(KEYSTORE) != null){    
    	  // lookup keystore passwords      
    	  String keystorepass = ServiceLocator.getInstance().getString("java:comp/env/keyStorePass");      
    	  if (keystorepass == null)
    		  throw new IllegalArgumentException("Missing keyStorePass property.");
    	  try {
    		  KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
    		  keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(KEYSTORE)).getBytes())),keystorepass.toCharArray());
    		  
    		  this.privateSignKey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
    		  this.privateDecKey = (PrivateKey) keystore.getKey(PRIVATEDECKEYALIAS, null);      
    		  
    		  this.publicSignKey = keystore.getCertificateChain(PRIVATESIGNKEYALIAS)[0].getPublicKey();
    		  this.encCert =  keystore.getCertificateChain(PRIVATEDECKEYALIAS)[0];
    		  this.publicEncKey = this.encCert.getPublicKey();
    		  
    	  } catch (Exception e) {
    		  throw new IllegalKeyStoreException(e);
    	  }
    	  
    	  data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_P12));        
      } 
   }
    
   /**
    * Method that generates the keys that will be used by the CAToken.
    */
   public void generateKeys(CATokenInfo catokeninfo) throws Exception{  

	   // Get key store password
	   String keystorepass = ServiceLocator.getInstance().getString("java:comp/env/keyStorePass");      
       // Currently only RSA keys are supported
       SoftCATokenInfo info = (SoftCATokenInfo) catokeninfo;       
       String signkeyspec = info.getSignKeySpec();  
       KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
       keystore.load(null, null);
       
       // generate sign keys.
       KeyPair signkeys = KeyTools.genKeys(signkeyspec, info.getSignKeyAlgorithm());
       // generate dummy certificate
       Certificate[] certchain = new Certificate[1];
       certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, signkeys.getPrivate(), signkeys.getPublic(), info.getSignatureAlgorithm(), true);
       
       keystore.setKeyEntry(PRIVATESIGNKEYALIAS,signkeys.getPrivate(),null, certchain);             
       
       // generate enc keys.  
       // Encryption keys must be RSA still
       String enckeyspec = info.getEncKeySpec();  
       KeyPair enckeys = KeyTools.genKeys(enckeyspec, info.getEncKeyAlgorithm());
       // generate dummy certificate
       certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, enckeys.getPrivate(), enckeys.getPublic(), info.getEncryptionAlgorithm(), true);
       this.encCert = certchain[0]; 
       keystore.setKeyEntry(PRIVATEDECKEYALIAS,enckeys.getPrivate(),null,certchain);              
       java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       keystore.store(baos, keystorepass.toCharArray());
       data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));
       data.put(SIGNKEYSPEC, signkeyspec);
       data.put(SIGNKEYALGORITHM, info.getSignKeyAlgorithm());
       data.put(SIGNATUREALGORITHM, info.getSignatureAlgorithm());
       data.put(ENCKEYSPEC, enckeyspec);
       data.put(ENCKEYALGORITHM, info.getEncKeyAlgorithm());
       data.put(ENCRYPTIONALGORITHM, info.getEncryptionAlgorithm());
       // initalize CAToken
       this.publicSignKey  = signkeys.getPublic();
       this.privateSignKey = signkeys.getPrivate();
              
       this.publicEncKey  = enckeys.getPublic();
       this.privateDecKey = enckeys.getPrivate();
   }
   
   /**
    * Method that import CA token keys from a P12 file. Was originally used when upgrading from 
    * old EJBCA versions. Only supports SHA1 and SHA256 with RSA or ECDSA.
    */
   public void importKeysFromP12(PrivateKey p12privatekey, PublicKey p12publickey, PrivateKey p12PrivateEncryptionKey,
		   							PublicKey p12PublicEncryptionKey, Certificate[] caSignatureCertChain) throws Exception{
      // lookup keystore passwords      
      InitialContext ictx = new InitialContext();
      String keystorepass = (String) ictx.lookup("java:comp/env/keyStorePass");      
      if (keystorepass == null)
        throw new IllegalArgumentException("Missing keyStorePass property.");
        
       // Currently only RSA keys are supported
       KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
       keystore.load(null,null);

       // Assume that the same hash algorithm is used for signing that was used to sign this CA cert
	   String certSignatureAlgorithm = ((X509Certificate) caSignatureCertChain[0]).getSigAlgName();
       String signatureAlgorithm = null;
       String keyAlg = null;
       if ( p12publickey instanceof RSAPublicKey ) {
    	   keyAlg  = CATokenInfo.KEYALGORITHM_RSA;
    	   if (certSignatureAlgorithm.indexOf("256") == -1) {
    		   signatureAlgorithm = CATokenInfo.SIGALG_SHA1_WITH_RSA;
    	   } else {
    		   signatureAlgorithm = CATokenInfo.SIGALG_SHA256_WITH_RSA;
    	   }
       } else {
    	   keyAlg = CATokenInfo.KEYALGORITHM_ECDSA;
    	   if (certSignatureAlgorithm.indexOf("256") == -1) {
    		   signatureAlgorithm = CATokenInfo.SIGALG_SHA1_WITH_ECDSA;
    	   } else {
    		   signatureAlgorithm = CATokenInfo.SIGALG_SHA256_WITH_ECDSA;
    	   }
       }
       
       // import sign keys.
       String keyspec = null;
       if ( p12publickey instanceof RSAPublicKey ) {
	       keyspec = Integer.toString( ((RSAPublicKey) p12publickey).getModulus().bitLength() );
	       log.debug("KeySize="+keyspec);
       } else {
	       	Enumeration en = ECNamedCurveTable.getNames();
	    	while ( en.hasMoreElements() ) {
	    		String currentCurveName = (String) en.nextElement();
	    		if ( (ECNamedCurveTable.getParameterSpec(currentCurveName)).getCurve().equals( ((ECPrivateKey) p12privatekey).getParameters().getCurve() ) ) {
	    			keyspec = currentCurveName;
	    			break;
	    		}
	    	}

    	   if ( keyspec==null ) {
        	   keyspec = "unknown";
    	   }
    	   p12privatekey = (ECPrivateKey) p12privatekey;
    	   p12publickey = (ECPublicKey) p12publickey;
    	   log.debug("ECName="+keyspec);
       }
       keystore.setKeyEntry(PRIVATESIGNKEYALIAS, p12privatekey, null, caSignatureCertChain);       
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
       if ( p12PublicEncryptionKey == null ||  p12PrivateEncryptionKey == null ) {
           enckeys = KeyTools.genKeys(keyspec, keyAlg);
       }
       else {
    	   enckeys = new KeyPair(p12PublicEncryptionKey, p12PrivateEncryptionKey);
       }
       // generate dummy certificate
       Certificate[] certchain = new Certificate[1];
       certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, enckeys.getPrivate(), enckeys.getPublic(), encryptionSignatureAlgorithm, true);
       this.encCert = certchain[0]; 
       keystore.setKeyEntry(PRIVATEDECKEYALIAS,enckeys.getPrivate(),null,certchain);              
     
       java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       keystore.store(baos, keystorepass.toCharArray());
       data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));
       data.put(ENCKEYSPEC, keyspec);
       data.put(ENCKEYALGORITHM, keyAlg);
       data.put(ENCRYPTIONALGORITHM, encryptionSignatureAlgorithm);
       
       // initalize CAToken
       this.publicSignKey  = p12publickey;
       this.privateSignKey = p12privatekey;
       
       this.publicEncKey  = enckeys.getPublic();
       this.privateDecKey = enckeys.getPrivate();
   }
   
   public CATokenInfo getCATokenInfo(){
     SoftCATokenInfo info = new SoftCATokenInfo();
     
     info.setSignKeySpec((String) data.get(SIGNKEYSPEC));
     info.setSignKeyAlgorithm((String) data.get(SIGNKEYALGORITHM));  
     info.setSignatureAlgorithm((String) data.get(SIGNATUREALGORITHM));
     
     info.setEncKeySpec((String) data.get(ENCKEYSPEC));
     info.setEncKeyAlgorithm((String) data.get(ENCKEYALGORITHM));  
     info.setEncryptionAlgorithm((String) data.get(ENCRYPTIONALGORITHM));
     
     return info;
   }
   
   /**
    * Updates the CAToken data saved in database.
    */
    public void updateCATokenInfo(CATokenInfo catokeninfo){
       // Do nothing, no data can be updated after the keys are generated.                   
    }
   
   /**
    * @see org.ejbca.core.model.ca.catoken.CAToken
    * 
    * @return PrivateKey object
    */
    public PrivateKey getPrivateKey(int purpose){       
      if(purpose == SecConst.CAKEYPURPOSE_KEYENCRYPT)
      	return this.privateDecKey;
      	
      return privateSignKey;        
    }

   /**
    * @see org.ejbca.core.model.ca.catoken.CAToken
    *
    * @return PublicKey object
    */
    public PublicKey getPublicKey(int purpose){
     if(purpose == SecConst.CAKEYPURPOSE_KEYENCRYPT)
       return this.publicEncKey;
     
      return publicSignKey;        
    }
    

    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public String getProvider(){
      return PROVIDER;  
    }

    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
    		// New version of the class, upgrade
			String msg = intres.getLocalizedMessage("catoken.upgradesoft", new Float(getVersion()));
            log.info(msg);
            if(data.get(SIGNKEYALGORITHM) == null) {
            	String oldKeyAlg = (String)data.get(KEYALGORITHM);            	
                data.put(SIGNKEYALGORITHM, oldKeyAlg);
                data.put(ENCKEYALGORITHM, oldKeyAlg);
            }            
            if(data.get(SIGNKEYSPEC) == null) {
            	Integer oldKeySize = ((Integer) data.get(KEYSIZE));
                data.put(SIGNKEYSPEC, oldKeySize.toString());
                data.put(ENCKEYSPEC, oldKeySize.toString());
            }
            if(data.get(ENCRYPTIONALGORITHM) == null) {
            	String signAlg = (String)data.get(SIGNATUREALGORITHM);            	
                data.put(ENCRYPTIONALGORITHM, signAlg);
            }
            
    		data.put(VERSION, new Float(LATEST_VERSION));
    	}  
    }

	/**
	 * Method doing nothing.
	 * 
	 * @see org.ejbca.core.model.ca.catoken.CAToken#activate(java.lang.String)
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		// Do nothing		
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CAToken#deactivate()
	 */
	public boolean deactivate() {
		// Do nothing		
		return true;
	}
    
    
}

