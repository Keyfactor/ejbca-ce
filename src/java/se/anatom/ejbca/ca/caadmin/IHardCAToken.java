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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;

import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;


/** Handles maintenance of the hardware device producing signatures and handling the private key.
 *  All HardCAToken plug-ins must implement this interface.
 * 
 * 
 * @version $Id: IHardCAToken.java,v 1.2 2005-05-24 09:32:53 herrvendil Exp $
 */
public interface IHardCAToken {

	public static final int STATUS_ACTIVE  = 1;
	public static final int STATUS_OFFLINE = 2;
	
   /** 
    * Method called after creation of instance. Gives the object it's properties.
    *
    */	
	public abstract void init(Properties properties, String signaturealgorithm);
	
	/**
	 *  Method that returns the current status of the catoken.
	 * 
	 *  Should return one of the IHardCAToken.STATUS_.. values 
	 */
	public abstract int getCATokenStatus();
	
    /**
     * Method used to activate HardCATokens when connected after being offline.
     * 
     * @param authenticationcode used to unlock catoken, i.e PIN for smartcard HSMs
     * @throws CATokenOfflineException if CAToken is not available or connected.
     * @throws CATokenAuthenticationFailedException with error message if authentication to HardCATokens fail.
     */
    public abstract void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException;    

    /**
     * Method used to deactivate HardCATokens. 
     * Used to set a CAToken too offline status and to reset the HSMs authorization code.
     * 
     * @return true if deactivation was successful.
     */
    public abstract boolean deactivate();    
    
    /** Returns the private key (if possible) of token.
    *
    * @param purpose should be SecConst.CAKEYPURPOSE_CERTSIGN, SecConst.CAKEYPURPOSE_CRLSIGN or SecConst.CAKEYPURPOSE_KEYENCRYPT 
    * @throws CATokenOfflineException if CAToken is not available or connected.
    * @return PrivateKey object
    */
    public abstract PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException;

    /** Returns the public key (if possible) of token.
    *
    * @param purpose should be SecConst.CAKEYPURPOSE_CERTSIGN, SecConst.CAKEYPURPOSE_CRLSIGN or SecConst.CAKEYPURPOSE_KEYENCRYPT    
    * @throws CATokenOfflineException if CAToken is not available or connected.
    * @return PublicKey object
    */
    public abstract PublicKey getPublicKey(int purpose) throws CATokenOfflineException;
    
    
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public abstract String getProvider();

    
}
