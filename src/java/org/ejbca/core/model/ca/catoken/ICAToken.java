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
 *  All CAToken plug-ins must implement this interface.
 * 
 * 
 * @version $Id$
 */
public interface ICAToken {

    static final int STATUS_ACTIVE  = 1;
    static final int STATUS_OFFLINE = 2;

    /** Auto activation property that can be defined in CA token properties */
    static final String AUTOACTIVATE_PIN_PROPERTY = "pin";
    /** Previous sequence (matching KeyString.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS key) that can be set in CA token properties */
    static final String PREVIOUS_SEQUENCE_PROPERTY = "previousSequence";
    /** Keyspec that is used as first choice when generating new keys in the GUI of form "1024" for RSA keys, "DSA1024" for DSA keys and secp256r1 for EC keys */
    static final String KEYSPEC_PROPERTY = "keyspec";

    /**
     * Method called after creation of instance. Gives the object it's properties.
     * 
     * @param properties CA Token properties, as entered for all HSM tokens, can be null for tokens that don't need it
     * @param data HashMap data as created internally for Soft tokens, can be null for tokens that don't need it
     * @param signaturealgorithm the signature algorithm used by the CA
     * @param caid unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @throws Exception
     */
    void init(Properties properties, HashMap data, String signaturealgorithm, int caid) throws Exception;

    /**
     *  Method that returns the current status of the catoken.
     *
     *  Should return one of the ICAToken.STATUS_.. values 
     */
    int getCATokenStatus();

    /**
     * Method used to activate HardCATokens when connected after being offline.
     * 
     * @param authenticationcode used to unlock catoken, i.e PIN for smartcard HSMs
     * @throws CATokenOfflineException if CAToken is not available or connected.
     * @throws CATokenAuthenticationFailedException with error message if authentication to HardCATokens fail.
     */
    void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException;    

    /**
     * Method used to deactivate HardCATokens. 
     * Used to set a CAToken too offline status and to reset the HSMs authorization code.
     * 
     * @return true if deactivation was successful.
     * @throws Exception 
     */
    boolean deactivate() throws Exception;

    /** Returns the private key (if possible) of token.
    *
    * @param purpose should be SecConst.CAKEYPURPOSE_CERTSIGN, SecConst.CAKEYPURPOSE_CRLSIGN or SecConst.CAKEYPURPOSE_KEYENCRYPT 
    * @throws CATokenOfflineException if CAToken is not available or connected.
    * @return PrivateKey object
    */
    PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException;

    /** Returns the public key (if possible) of token.
    *
    * @param purpose should be SecConst.CAKEYPURPOSE_CERTSIGN, SecConst.CAKEYPURPOSE_CRLSIGN or SecConst.CAKEYPURPOSE_KEYENCRYPT    
    * @throws CATokenOfflineException if CAToken is not available or connected.
    * @return PublicKey object
    */
    PublicKey getPublicKey(int purpose) throws CATokenOfflineException;

    /**
     * Returns the key label configured for a specific key purpose. Key labels are KeyStrings.CAKEYPURPOSE_XXX
     * @param purpose
     */
    String getKeyLabel(int purpose);

    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signing device implementation.
     * @return String the name of the Provider
     */
    String getProvider();

    /** Returns the crypto Provider that should be used to encrypt/decrypt things with
     *  the PrivateKey object returned by this signing device implementation.
     *  In most cases this is the same as the signature provider.
     * @return String the name of the Provider
     */
    String getJCEProvider();

    /**
     * Resets token. Might cure HW failures. It is up to each implementation to implement this or not.
     */
    void reset();
    
    /** Updates the Properties for the CA token. Call this method when a new key string, autoactivation PIN has been set
     *  and the init method on the catoken is not called. 
     *  Does not update properties that is only used when token is created, for example P11 slot, this is only updated on recreation of the token.
     * @param properties Properties containing the new key properties or other properties, such as activation PIN
     */
    void updateProperties(Properties properties);

}
