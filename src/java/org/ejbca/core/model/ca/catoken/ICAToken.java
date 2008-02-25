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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Properties;




/** Handles maintenance of the hardware device producing signatures and handling the private key.
 *  All HardCAToken plug-ins must implement this interface.
 * 
 * 
 * @version $Id: ICAToken.java,v 1.3 2008-02-25 15:55:18 anatom Exp $
 */
public interface ICAToken {

	public static final int STATUS_ACTIVE  = 1;
	public static final int STATUS_OFFLINE = 2;
	
    public static final String AUTOACTIVATE_PIN_PROPERTY = "pin";
    
   /** 
    * Method called after creation of instance. Gives the object it's properties.
    * 
    * @param properties CA Token properties, as entered for all HSM tokens, can be null for tokens that don't need it
    * @param data HashMap data as created internally for Soft tokens, can be null for tokens that don't need it
    * @param signaturealgorithm the signature algorithm used by the CA
    * 
    * @throws Exception 
    */	
    public void init(Properties properties, HashMap data, String signaturealgorithm) throws Exception;
	
	/**
	 *  Method that returns the current status of the catoken.
	 * 
	 *  Should return one of the ICAToken.STATUS_.. values 
	 */
	public int getCATokenStatus();
	
    /**
     * Method used to activate HardCATokens when connected after being offline.
     * 
     * @param authenticationcode used to unlock catoken, i.e PIN for smartcard HSMs
     * @throws CATokenOfflineException if CAToken is not available or connected.
     * @throws CATokenAuthenticationFailedException with error message if authentication to HardCATokens fail.
     */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException;    

    /**
     * Method used to deactivate HardCATokens. 
     * Used to set a CAToken too offline status and to reset the HSMs authorization code.
     * 
     * @return true if deactivation was successful.
     */
    public boolean deactivate();    
    
    /** Returns the private key (if possible) of token.
    *
    * @param purpose should be SecConst.CAKEYPURPOSE_CERTSIGN, SecConst.CAKEYPURPOSE_CRLSIGN or SecConst.CAKEYPURPOSE_KEYENCRYPT 
    * @throws CATokenOfflineException if CAToken is not available or connected.
    * @return PrivateKey object
    */
    public PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException;

    /** Returns the public key (if possible) of token.
    *
    * @param purpose should be SecConst.CAKEYPURPOSE_CERTSIGN, SecConst.CAKEYPURPOSE_CRLSIGN or SecConst.CAKEYPURPOSE_KEYENCRYPT    
    * @throws CATokenOfflineException if CAToken is not available or connected.
    * @return PublicKey object
    */
    public PublicKey getPublicKey(int purpose) throws CATokenOfflineException;
    
    
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signing device implementation.
     * @return String the name of the Provider
     */
    public String getProvider();
    
    /** Returns the crypto Provider that should be used to encrypt/decrypt things with
     *  the PrivateKey object returned by this signing device implementation.
     *  In most cases this is the same as the signature provider.
     * @return String the name of the Provider
     */
    public String getJCEProvider();
}
