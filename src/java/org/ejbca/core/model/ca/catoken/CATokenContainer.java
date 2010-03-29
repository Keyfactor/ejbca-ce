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
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.ejbca.core.model.UpgradeableDataHashMap;



/** Handles maintenance of the device producing signatures and handling the private key.
 * 
 * @version $Id$
 */
public abstract class CATokenContainer extends UpgradeableDataHashMap implements java.io.Serializable{

    public static final String CATOKENTYPE = "catokentype";
    
    protected static final String SIGNATUREALGORITHM = "signaturealgorithm";
    protected static final String ENCRYPTIONALGORITHM = "encryptionalgorithm";

    /** A sequence for the keys, updated when keys are re-generated */
    protected static final String SEQUENCE = "sequence";
    /** Format of the key sequence */
    protected static final String SEQUENCE_FORMAT = "sequenceformat";
    
    /** constants needed for soft CA keystores */
    protected static final String SIGNKEYSPEC       = "SIGNKEYSPEC";
    protected static final String ENCKEYSPEC        = "ENCKEYSPEC";
    protected static final String SIGNKEYALGORITHM  = "SIGNKEYALGORITHM";
    protected static final String ENCKEYALGORITHM   = "ENCKEYALGORITHM";
    protected static final String KEYSTORE          = "KEYSTORE";

    /** Old provided for upgrade purposes from 3.3. -> 3.4 */
    protected static final String KEYALGORITHM  = "KEYALGORITHM";
    /** Old provided for upgrade purposes from 3.3. -> 3.4 */
    protected static final String KEYSIZE       = "KEYSIZE";

   /**
    *  Returns information about this CAToken.
    */
    public abstract CATokenInfo getCATokenInfo();  

    /**
     *  Returns the type of CA token, from CATokenConstants.
     *  @return integer one of CATokenConstants.CATOKENTYPE_XXX
     *  @see CATokenConstants.CATOKENTYPE_XXX
     */
     public abstract int getCATokenType();  

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
     * @throws Exception 
     */
    public abstract boolean deactivate() throws Exception;    
   
    
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
     *  the PrivateKey object returned by this signing device implementation.
     * @return String the name of the Provider
     */
    public abstract String getProvider();
    
    /** Returns the crypto Provider that should be used to encrypt/decrypt things with
     *  the PrivateKey object returned by this signing device implementation.
     * @return String the name of the Provider
     */
    public abstract String getJCEProvider();

	/**
	 * Method that generates the keys that will be used by the CAToken.
	 * The method can be used to generate keys for an initial CA token or to renew Certificate signing keys. 
	 * If setstatustowaiting is true and you generate new keys, the new keys will be available as SecConst.CAKEYPURPOSE_CERTSIGN.
	 * If setstatustowaiting is false and you generate new keys, the new keys will be available as SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
	 * 
	 * @param authenticationCode the password used to encrypt the keystore, laterneeded to activate CA Token
	 * @param renew flag indicating if the keys are renewed instead of created fresh. Renewing keys does not 
	 * create new encryption keys, since this would make it impossible to decrypt old stuff.
	 * @param activate flag indicating if the new keys should be activated immediately or or they should be added as "next" signing key. 
	 * Using true here makes it possible to generate certificate renewal requests for external CAs still using the old keys until the response is received. 
	 */
	public abstract void generateKeys(String authenticationCode, boolean renew, boolean activate) throws Exception;  

	/** Activating the "next" signing key means:
	 * - move current signing key to previous signing to
	 * - move current sequence to previous sequence
	 * - move next signing key to current signing key
	 * - move next sequence to current sequence
	 * - remove next signing key mappings
	 * - remove next sequence
	 * 
	 * @param authenticationCode
	 * @throws CATokenOfflineException
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws CATokenAuthenticationFailedException
	 */
	public abstract void activateNextSignKey(String authenticationCode) throws CATokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, CATokenAuthenticationFailedException;
	
	/**
	 * Method that import CA token keys from a P12 file. Was originally used when upgrading from 
	 * old EJBCA versions. Only supports SHA1 and SHA256 with RSA or ECDSA.
	 */
	public abstract void importKeys(String authenticationCode, PrivateKey privatekey, PublicKey publickey, PrivateKey privateEncryptionKey,
			PublicKey publicEncryptionKey, Certificate[] caSignatureCertChain) throws Exception;

}
