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

import java.security.KeyStore;
import java.util.HashMap;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.util.Base64;

/** Handles maintenance of the soft devices producing signatures and handling the private key
 *  and stored in database.
 * 
 * @version $Id: SoftCAToken.java,v 1.11 2007-07-25 08:56:45 anatom Exp $
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

    public SoftCAToken() throws InstantiationException {
    	super();
    	log.debug("Creating SoftCAToken");
    }
    
    public void init(Properties properties, HashMap data, String signaturealgorithm) throws Exception {
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
	  init(null, properties, signaturealgorithm);
	  
      if(data.get(CATokenContainer.KEYSTORE) != null){    
    	  // lookup keystore passwords      
    	  String keystorepass = ServiceLocator.getInstance().getString("java:comp/env/keyStorePass");      
    	  if (keystorepass == null)
    		  throw new IllegalArgumentException("Missing keyStorePass property.");
    	  try {
    		  KeyStore keystore=KeyStore.getInstance("PKCS12", "BC");
    		  keystore.load(new java.io.ByteArrayInputStream(Base64.decode(((String) data.get(CATokenContainer.KEYSTORE)).getBytes())),keystorepass.toCharArray());    		  
              setKeys(keystore, keystorepass);
    	  } catch (Exception e) {
    		  throw new IllegalKeyStoreException(e);
    	  }
      } 
   }
    
   
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public String getProvider(){
      return PROVIDER;  
    }
    
	/**
	 * Method doing nothing.
	 * 
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#activate(java.lang.String)
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		// Do nothing		
	}

	/**
	 * @see org.ejbca.core.model.ca.catoken.CATokenContainer#deactivate()
	 */
	public boolean deactivate() {
		// Do nothing		
		return true;
	}
    
    
}

