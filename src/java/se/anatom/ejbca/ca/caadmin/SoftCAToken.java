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
 
package se.anatom.ejbca.ca.caadmin;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;
import se.anatom.ejbca.ca.exception.IllegalKeyStoreException;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;
/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: SoftCAToken.java,v 1.13 2005-03-22 13:51:06 anatom Exp $
 */
public class SoftCAToken extends CAToken implements java.io.Serializable{

    /** Log4j instance */
    private static Logger log = Logger.getLogger(SoftCAToken.class);

    public static final float LATEST_VERSION = 1; 
    
    private static final String  PROVIDER = "BC";

    private PrivateKey privateSignKey = null;
    private PrivateKey privateDecKey  = null;
    private PublicKey  publicSignKey  = null;
    private PublicKey  publicEncKey   = null;
    private Certificate encCert = null;
    
    private static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";
    private static final String PRIVATEDECKEYALIAS = "privatedeckeyalias";
    
    protected static final String KEYSIZE       = "KEYSIZE";
    protected static final String KEYALGORITHM  = "KEYALGORITHM";
    protected static final String KEYSTORE      = "KEYSTORE";
    
    public SoftCAToken(){
      data = new HashMap();   
      data.put(CATOKENTYPE, new Integer(CATokenInfo.CATOKENTYPE_P12));
      data.put(VERSION, new Float(LATEST_VERSION));
    }
    
    public SoftCAToken(HashMap data) throws IllegalArgumentException, IllegalKeyStoreException {
      loadData(data);  
      if(data.get(KEYSTORE) != null){    
         // lookup keystore passwords      
         String keystorepass = null;
         try {
             InitialContext ictx = new InitialContext();
             keystorepass = (String) ictx.lookup("java:comp/env/keyStorePass");      
             if (keystorepass == null)
                 throw new IllegalArgumentException("Missing keyStorePass property.");
         } catch (NamingException ne) {
             throw new IllegalArgumentException("Missing keyStorePass property.");
         }
               
        try {
            KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(KEYSTORE)).getBytes())),keystorepass.toCharArray());
      
            this.privateSignKey = (PrivateKey) keystore.getKey(PRIVATESIGNKEYALIAS, null);
            this.privateDecKey = (PrivateKey) keystore.getKey(PRIVATEDECKEYALIAS, null);      
      
            this.publicSignKey = ((Certificate) keystore.getCertificateChain(PRIVATESIGNKEYALIAS)[0]).getPublicKey();
            this.encCert =  ((Certificate) keystore.getCertificateChain(PRIVATEDECKEYALIAS)[0]);
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
      // lookup keystore passwords      
      InitialContext ictx = new InitialContext();
      String keystorepass = (String) ictx.lookup("java:comp/env/keyStorePass");      
      if (keystorepass == null)
        throw new IllegalArgumentException("Missing keyStorePass property.");
        
       // Currently only RSA keys are supported
       SoftCATokenInfo info = (SoftCATokenInfo) catokeninfo;       
       int keysize = info.getKeySize();  
       KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
       keystore.load(null, null);
       
       // generate sign keys.
       KeyPair signkeys = KeyTools.genKeys(keysize);
       // generate dummy certificate
       Certificate[] certchain = new Certificate[1];
       certchain[0] = CertTools.genSelfCert("CN=dummy", 36500, null, signkeys.getPrivate(), signkeys.getPublic(), true);
       
       keystore.setKeyEntry(PRIVATESIGNKEYALIAS,signkeys.getPrivate(),null, certchain);             
       
       // generate enc keys.  
       KeyPair enckeys = KeyTools.genKeys(keysize);
       // generate dummy certificate
       certchain[0] = CertTools.genSelfCert("CN=dummy2", 36500, null, enckeys.getPrivate(), enckeys.getPublic(), true);
       this.encCert = certchain[0]; 
       keystore.setKeyEntry(PRIVATEDECKEYALIAS,enckeys.getPrivate(),null,certchain);              
       java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       keystore.store(baos, keystorepass.toCharArray());
       data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));
       data.put(KEYSIZE, new Integer(keysize));
       data.put(KEYALGORITHM, info.getAlgorithm());
       data.put(SIGNATUREALGORITHM, info.getSignatureAlgorithm());
       // initalize CAToken
       this.publicSignKey  = signkeys.getPublic();
       this.privateSignKey = signkeys.getPrivate();
              
       this.publicEncKey  = enckeys.getPublic();
       this.privateDecKey = enckeys.getPrivate();
   }
   
   /**
    * Method that import CA token keys from old P12 file. Should only be used when upgrading from 
    * old EJBCA versions.
    */
   public void importKeysFromP12(PrivateKey p12privatekey, PublicKey p12publickey) throws Exception{  
      // lookup keystore passwords      
      InitialContext ictx = new InitialContext();
      String keystorepass = (String) ictx.lookup("java:comp/env/keyStorePass");      
      if (keystorepass == null)
        throw new IllegalArgumentException("Missing keyStorePass property.");
        
       // Currently only RSA keys are supported
       KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
       keystore.load(null,null);
     
       // import sign keys.
       int keysize = ((RSAPublicKey) p12publickey).getModulus().bitLength();
       log.debug("KeySize="+keysize);
       Certificate[] certchain = new Certificate[1];
       certchain[0] = CertTools.genSelfCert("CN=dummy1", 1000, null, p12privatekey, p12publickey, true);
       keystore.setKeyEntry(PRIVATESIGNKEYALIAS, p12privatekey,null,certchain);       
     
       // generate enc keys.  
       KeyPair enckeys = KeyTools.genKeys(keysize);
       certchain[0] = CertTools.genSelfCert("CN=dummy2", 1000, null, enckeys.getPrivate(), enckeys.getPublic(), true);
       this.encCert = certchain[0];
       keystore.setKeyEntry(PRIVATEDECKEYALIAS,enckeys.getPrivate(),null,certchain);       
     
       java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       keystore.store(baos, keystorepass.toCharArray());
       data.put(KEYSTORE, new String(Base64.encode(baos.toByteArray())));
       data.put(KEYSIZE, new Integer(keysize));
       data.put(KEYALGORITHM, SoftCATokenInfo.KEYALGORITHM_RSA);
       data.put(SIGNATUREALGORITHM, CATokenInfo.SIGALG_SHA1_WITH_RSA);
       
       // initalize CAToken
       this.publicSignKey  = p12publickey;
       this.privateSignKey = p12privatekey;
       
       this.publicEncKey  = enckeys.getPublic();
       this.privateDecKey = enckeys.getPrivate();
   }   
   
   public CATokenInfo getCATokenInfo(){
     SoftCATokenInfo info = new SoftCATokenInfo();
     
     info.setKeySize(((Integer) data.get(KEYSIZE)).intValue());
     info.setAlgorithm((String) data.get(KEYALGORITHM));  
     info.setSignatureAlgorithm((String) data.get(SIGNATUREALGORITHM));
        
     return info;
   }
   
   /**
    * Updates the CAToken data saved in database.
    */
    public void updateCATokenInfo(CATokenInfo catokeninfo){
       // Do nothing, no data can be updated after the keys are generated.                   
    }
   
   /**
    * @see se.anatom.ejbca.ca.caadmin.CAToken
    * 
    * @return PrivateKey object
    */
    public PrivateKey getPrivateKey(int purpose){       
      if(purpose == SecConst.CAKEYPURPOSE_KEYENCRYPT)
      	return this.privateDecKey;
      	
      return privateSignKey;        
    }

   /**
    * @see se.anatom.ejbca.ca.caadmin.CAToken
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
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade

        data.put(VERSION, new Float(LATEST_VERSION));
      }  
    }

	/**
	 * Method doing nothing.
	 * 
	 * @see se.anatom.ejbca.ca.caadmin.CAToken#activate(java.lang.String)
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		// Do nothing		
	}

	/**
	 * @see se.anatom.ejbca.ca.caadmin.CAToken#deactivate()
	 */
	public boolean deactivate() {
		// Do nothing		
		return true;
	}
    
    
}

