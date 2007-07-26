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

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.util.Base64;

/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: SoftCAToken.java,v 1.15 2007-07-26 09:11:36 anatom Exp $
 */
public class SoftCAToken extends BaseCAToken {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SoftCAToken.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** When upgradeing this version, you must up the version of the CA as well, 
     * otherwise the upgraded CA token will not be stored in the database.
     */
    public static final float LATEST_VERSION = 3; 
    
    private static final String  PROVIDER = "BC";

    protected static final String PRIVATESIGNKEYALIAS = "privatesignkeyalias";
    protected static final String PRIVATEDECKEYALIAS = "privatedeckeyalias";

    /** Cache for holding the keystore data that has been read from the database. Requires a password to activate */
    private byte[] keyStoreData = null;
    
    public SoftCAToken() throws InstantiationException {
    	super();
    	log.debug("Creating SoftCAToken");
    }
    
    public void init(Properties properties, HashMap data, String signaturealgorithm) throws Exception {

    	if(data.get(CATokenContainer.KEYSTORE) != null){ 
    		keyStoreData =  Base64.decode(((String) data.get(CATokenContainer.KEYSTORE)).getBytes());
    	}

    	// A soft CA have two keys in the CA keystore, the corresponding Properties would be
    	//    defaultKey PRIVATEDECKEYALIAS (privatedeckeyalias)
    	//    certSignKey PRIVATESIGNKEYALIAS (privatesignkeyalias)
    	//    crlSignKey PRIVATESIGNKEYALIAS (privatesignkeyalias)
    	if (properties == null) {
    		properties = new Properties();
    	}
    	properties.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING, PRIVATESIGNKEYALIAS);
    	properties.setProperty(KeyStrings.CAKEYPURPOSE_CRLSIGN_STRING, PRIVATESIGNKEYALIAS);
    	properties.setProperty(KeyStrings.CAKEYPURPOSE_DEFAULT_STRING, PRIVATEDECKEYALIAS);
    	// If we don't have an auto activation password set, we try to use the default one if it works to load the keystore with it
    	String autoPwd = properties.getProperty(AUTOACTIVATE_PIN_PROPERTY);
    	if (autoPwd == null) {
    		String keystorepass = ServiceLocator.getInstance().getString("java:comp/env/keyStorePass");          		
    		if (keystorepass == null) {
    			log.error("Missing keyStorePass property. We can not autoActivate standard soft CA tokens.");
    			throw new IllegalArgumentException("Missing keyStorePass property.");		    		
    		}
    		// Test it first, don't set an incorrect password as autoactivate password
    		boolean okPwd = true;
    		try {
    			loadKeyStore(keyStoreData, keystorepass);
    			log.debug("Succeded to load keystore with password");
    		} catch (Exception e) {
    			// Don't do it
    			okPwd = false;
    			log.debug("Failed to load keystore with password");
    		}
    		if (okPwd) {
    			properties.setProperty(AUTOACTIVATE_PIN_PROPERTY, keystorepass);	    		
    		}
    	} else {
    		//log.debug("Soft CA Token has autoactivation property set." + "'"+autoPwd+"'");
    		log.debug("Soft CA Token has autoactivation property set.");
    	}
      
	  init(null, properties, signaturealgorithm, true);
   }
    
   
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public String getProvider(){
      return PROVIDER;  
    }
    
	/**
	 * Loads the keystore and retrieves the keys.
	 * 
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#activate(java.lang.String)
	 */
    public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
    	try {
    		KeyStore keystore = loadKeyStore(keyStoreData, authenticationcode);
    		setKeys(keystore, authenticationcode);
    	} catch (Exception e) {
    		String msg = intres.getLocalizedMessage("catoken.erroractivate", e.getMessage());
            log.info(msg);
    		log.info(e);
    		CATokenOfflineException oe = new CATokenOfflineException(e.getMessage());
    		oe.initCause(e);
    		throw oe;
    	}
		String msg = intres.getLocalizedMessage("catoken.activated", "Soft");
        log.info(msg);
    }
    
    private KeyStore loadKeyStore(byte[] ksdata, String keystorepass) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, NoSuchProviderException {
		KeyStore keystore=KeyStore.getInstance("PKCS12", PROVIDER);
		keystore.load(new java.io.ByteArrayInputStream(ksdata),keystorepass.toCharArray());
		return keystore;
    }
}

