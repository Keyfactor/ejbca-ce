/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/** Handles operations of the device producing signatures and handling the private key.
 *  All Crypto Token plug-ins must implement this interface.
 *
 * @version $Id$
 */
public interface CryptoToken extends Serializable {

    static final int STATUS_ACTIVE  = 1;
    static final int STATUS_OFFLINE = 2;

    /** Auto activation property that can be defined in Crypto token properties */
    static final String AUTOACTIVATE_PIN_PROPERTY = "pin";
    /** Boolean indicating if it should be allowed to extract private keys */
    static final String ALLOW_EXTRACTABLE_PRIVATE_KEY = "allow.extractable.privatekey";
    /** Boolean indicating if explicit ECC parameters should be used, instead of named curves which is standard. 
     *  Explicit parameters are only used by ICAO CSCA and DS certificates as defined in ICAO 9303.
     */
    static final String EXPLICIT_ECC_PUBLICKEY_PARAMETERS = "explicit.ecc.publickey.parameters";
    /** */
    static final String TOKENNAME_PROPERTY = "tokenName";

    /**
     * Method called after creation of instance. Gives the object it's properties.
     *
     * Info contains Crypto Token properties, as entered for all tokens. Properties can create properties used by extending or wrapping classes so the implementing
     * class should not delete or remove properties that are unknown to it, but keep them transparently.
     * Data contains Crypto Token data, can be null for tokens that don't need it.
     *
     * @param properties Properties info used to create token, new token or init existing token
     * @param data byte[] data as created internally for tokens, can be null for tokens that don't need it
     * @param id unique ID of the user of the token, the id is user defined and not used internally for anything but logging.
     * @throws Exception
     */
    void init(Properties properties, byte[] data, int id) throws Exception;

    /** Gets the id that was passed as parameter to init
     *
     */
    int getId();

    /**
     * Method used to activate Crypto Tokens when connected after being offline.
     *
     * @param authenticationcode used to unlock crypto token, i.e PIN for smartcard HSMs. This parameter might be ignored, e.g. for auto-activated soft tokens.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected.
     * @throws CryptoTokenAuthenticationFailedException with error message if authentication to tokens fail.
     */
    void activate(char[] authenticationcode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /**
     * Method used to deactivate tokens.
     * Used to set a Crypto Token to offline status and to reset the HSMs authorization code.
     *
     */
    void deactivate();

    /** Checks if an alias is in use by a Crypto Token
     * @param the alias that we want to check
     * @return true if there is a private, public or symmetric entry with this alias in the CryptoToken 
     */
    boolean isAliasUsed(String alias);

    /** Returns the private key (if possible) of token.
    * Note that this method does NOT check if the key is permitted to be extracted.
    *
    * @param alias the key alias to retrieve from the token
    * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
    * @return PrivateKey object
    */
    PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException;

    /** Returns the public key (if possible) of token.
    *
    * @param alias the key alias to retrieve from the token
    * @throws CryptoTokenOfflineException if Crypto Token is not available or connected
    * @return the public key, or null if key with the alias does not exist.
    */
    PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException;

    /** Returns the key (if possible) of token, used for symmetric keys. For assymmetric keys getPrivateKye and getPublic key is recommended..
    *
    * @param alias the key alias to retrieve from the token
    * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
    * @return Key object
    */
    Key getKey(String alias) throws CryptoTokenOfflineException;

    /** Deletes an entry in the crypto token
     *
     * @param alias is a reference to the entry in the token that should be deleted.

     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    void deleteEntry(String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException;

    /** Generates a key pair (asymmetric keys) in the crypto token.
     *
     * @param keySpec all decimal digits RSA key length, otherwise name of ECC curve or DSA key using syntax DSAnnnn
     * @param alias the name of the key pair in the crypto token
     */
    void generateKeyPair(final String keySpec, final String alias) throws InvalidAlgorithmParameterException,
            CryptoTokenOfflineException;

    /** Generates a key pair (asymmetric keys) in the crypto token. This method is used when you have an existing PublicKey and
     * want to generate a key of the same type. You can use KeyTools to get the AlgorithmParameterSpec from an existing PublicKey.
     * <pre>
     * AlgorithmParameterSpec spec = KeyTools.getKeyGenSpec(templatePublicKey);
     * </pre>
     *
     * @param spec AlgorithmParameterSpec describing the key pair to be generated
     * @param alias the name of the key pair in the crypto token
     */
    void generateKeyPair(final AlgorithmParameterSpec spec, final String alias) throws InvalidAlgorithmParameterException, CertificateException,
            IOException, CryptoTokenOfflineException;

    /** Generates a symmetric key.
     *
     * @param algorithm symmetric algorithm specified in http://download.oracle.com/javase/1.5.0/docs/api/index.html, suggest AES, DESede or DES
     * @param keysize keysize of symmetric key, suggest 128 or 256 for AES, 64 for 168 for DESede and 64 for DES
     * @param alias the alias the key will get in the keystore
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    void generateKey(final String algorithm, final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException,
    InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException;

    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signing device implementation.
     * @return String the name of the Provider
     */
    String getSignProviderName();

    /** Returns the crypto Provider that should be used to encrypt/decrypt things with
     *  the PrivateKey object returned by this signing device implementation.
     *  In most cases this is the same as the signature provider.
     * @return String the name of the Provider
     */
    String getEncProviderName();

    /**
     * Resets token. Might cure HW failures. It is up to each implementation to implement this or not.
     */
    void reset();

    /** @return user friendly identifier */
    String getTokenName();
    /** Set user friendly identifier */
    void setTokenName(String tokenName);
    
    /**
     *  Method that returns the current status of the crypto token.
     *
     *  Returns one of the CryptoToken.STATUS_.. values
     */
    int getTokenStatus();

    /** Return token properties, can be the same as passed to init, or an updated set
     *
     * @return Properties can be empty but should never be null
     */
    Properties getProperties();

    /** Updates dynamic properties for the crypto token. Call this method when a new key string, autoactivation PIN has been set
     *  and the init method on the crypto token is not called.
     *  Does not update properties that is only used when token is created, for example P11 slot, this is only updated on recreation of the token.
     * @param properties Properties containing the new key properties or other properties, such as activation PIN
     */
    void setProperties(Properties properties);

    /**
     * Stores a new key in this crypto token's keystore. 
     * 
     * @param alias The alias for the key
     * @param key The key to be stored
     * @param chain The associated key chain
     * @param password Password to this slot.
     * @throws KeyStoreException if keystore for this crypto token has not been initialized
     */
    void storeKey(String alias, Key key, Certificate chain[], char[] password) throws KeyStoreException;
    
    /** Stores keystore data (if any) to be used when initializing a new (existing) token with the init method
     *
     * @return byte[] with keystore data, can be null if not needed for initialization
     */
	byte[] getTokenData();

    /** Testing a keypair to see that it is usable
     *
     * @param alias the alias of the key pair to test
     * @throws InvalidKeyException if the public key can not be used to verify a string signed by the private key, because the key is wrong or the 
     * signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * @throws CryptoTokenOfflineException if the crypto token is offline
     */
    void testKeyPair(String alias) throws InvalidKeyException, CryptoTokenOfflineException; // NOPMD:this is not a junit test

    /**
     * This method extracts a PrivateKey from the keystore and wraps it, using a symmetric encryption key
     *
     * @param privKeyTransform - transformation algorithm - if CBC mode is requested, the following IV is used: 0x0000000000000000
     * @param encryptionKeyAlias - alias of the symmetric key that will encrypt the private key
     * @param privateKeyAlias - alias for the PrivateKey to be extracted
     * @return byte[] with the encrypted extracted key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws CryptoTokenOfflineException
     * @throws PrivateKeyNotExtractableException
     * @throws InvalidAlgorithmParameterException
     */
    byte[] extractKey(String privKeyTransform, String encryptionKeyAlias, String privateKeyAlias) throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, CryptoTokenOfflineException, PrivateKeyNotExtractableException, InvalidAlgorithmParameterException;

    /**
     * This method extracts a PrivateKey from the keystore and wraps it, using a symmetric encryption key. This method is used
     * when you need to supply additional information for the encryption algorithm, e.g: IvParameterSpec for CBC mode.
     *
     * @param privKeyTransform - transformation algorithm
     * @param spec - transformation algorithm spec (e.g: IvParameterSpec for CBC mode)
     * @param encryptionKeyAlias - alias of the symmetric key that will encrypt the private key
     * @param privateKeyAlias - alias for the PrivateKey to be extracted
     * @return byte[] with the encrypted extracted key
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws CryptoTokenOfflineException
     * @throws PrivateKeyNotExtractableException
     * @throws InvalidAlgorithmParameterException
     */
    byte[] extractKey(String privKeyTransform, AlgorithmParameterSpec spec, String encryptionKeyAlias, String privateKeyAlias) throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, CryptoTokenOfflineException, PrivateKeyNotExtractableException, InvalidAlgorithmParameterException;

    /**
     * Checks if generated private keys are allowed to be extracted.
     *
     * @return false if the private key is not extractable.
     */
    boolean doPermitExtractablePrivateKey();

    /**
     *
     * @return an enumeration of aliases from this token's key store.
     * @throws KeyStoreException if the keystore has not been initialized (loaded).
     * @throws CryptoTokenOfflineException if the keystore has not been initialized (loaded).
     */
    List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException;

    /** @return true if there is an auto activation PIN stored in the token */
    boolean isAutoActivationPinPresent();
    
}
