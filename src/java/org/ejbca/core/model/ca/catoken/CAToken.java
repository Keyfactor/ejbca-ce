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

import org.ejbca.core.model.UpgradeableDataHashMap;



/** Handles maintenance of the device producing signatures and handling the private key.
 * 
 * @version $Id: CAToken.java,v 1.1 2006-01-17 20:31:51 anatom Exp $
 */
public abstract class CAToken extends UpgradeableDataHashMap implements java.io.Serializable{
    
    public static final String CATOKENTYPE = "catokentype";
    
    protected static final String SIGNATUREALGORITHM = "signaturealgorithm";
   /**
    *  Returns information about this CAToken.
    */
    public abstract CATokenInfo getCATokenInfo();  
    
   /**
    * Updates the CAToken data saved in database.
    */
    public abstract void updateCATokenInfo(CATokenInfo catokeninfo);

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
    public abstract PrivateKey getPrivateKey(int purpose)  throws CATokenOfflineException;

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
