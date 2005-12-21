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

package se.anatom.ejbca.ca.caadmin.hardcatokens;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.caadmin.AvailableHardCAToken;
import se.anatom.ejbca.ca.caadmin.IHardCAToken;
import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;

/**
 * 
 * Class used as test and demonstrationclass when writing HardCAToken plug-ins as HSMs.
 * 
 * Observe: Remember to add a loadClass("thisclass") row to the HardCATokenManager.init() method when adding new plug-ins.

 * @author herrvendil
 * @version $Id: DummyHardCAToken.java,v 1.6 2005-12-21 12:50:33 anatom Exp $
 * 
 */
public class DummyHardCAToken implements IHardCAToken {
    /** Log4j instance */
	private static final Logger log = Logger.getLogger(DummyHardCAToken.class);
	
    /** The constructor of HardCAToken should throw an InstantiationException is the token can not
     * be created, if for example depending jar files for the particular HSM is not available.
     */
	public DummyHardCAToken(){
        AvailableHardCAToken token = HardCATokenManager.instance().getAvailableHardCAToken("se.anatom.ejbca.ca.caadmin.hardcatokens.DummyHardCAToken");
        if (token != null) {
            log.debug("Registered DummyHardCAToken succesfully.");
        }
	}
	
	/**
	 * This method should initalize this plug-in with the properties configured in the adminweb-GUI.
	 * 
	 */
	public void init(Properties properties, String signaturealgorithm) {
		log.debug("Init()");
          // Implement this.	  
	}
	

	/**
     * Method used to activate HardCATokens when connected after being offline.
     * 
     * @param authenticationcode used to unlock catoken, i.e PIN for smartcard HSMs
     * @throws CATokenOfflineException if CAToken is not available or connected.
     * @throws CATokenAuthenticationFailedException with error message if authentication to HardCATokens fail.
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
		log.debug("activate(" + authenticationcode +")");
        // Implement this.	  
	}
	
    /**
     * Method used to deactivate HardCATokens. 
     * Should reset the HSMs or smartcard.
     * 
     * @return true if deactivation was successful.
     */
    public boolean deactivate(){  
	  log.debug("deactivate()");
      // Implement this.	      	
      return true;	
    }
	
    
	/**
	 * Should return a reference to the private key used with the given purpose.
	 * 
	 * Purpose can have one of the following values: CAKEYPURPOSE_CERTSIGN, CAKEYPURPOSE_CRLSIGN or CAKEYPURPOSE_KEYENCRYPT    
	 */
	public PrivateKey getPrivateKey(int purpose) {
		log.debug("getPrivateKey(" + purpose + ")");
        // Implement this.	  
		return null;
	}
	
	/**
	 * Should return a reference to the public key used with the given purpose.
	 * 
	 * Purpose can have one of the following values: CAKEYPURPOSE_CERTSIGN, CAKEYPURPOSE_CRLSIGN or CAKEYPURPOSE_KEYENCRYPT    
	 */
	public PublicKey getPublicKey(int purpose) {
		log.debug("getPublicKey(" + purpose + ")");
        // Implement this.	  
		return null;
	}

	
	
    /** Should return the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
	public String getProvider() {
		log.debug("getProvider()");	  
        // Implement this.	  
		return null;
	}

	/**
	 *  Method that returns the current status of the catoken.
	 * 
	 *  Should return one of the IHardCAToken.STATUS_.. values 
	 */
	public int getCATokenStatus() {
		log.debug("getCATokenStatus()");
		// Implements this
		return 0;
	}


}
