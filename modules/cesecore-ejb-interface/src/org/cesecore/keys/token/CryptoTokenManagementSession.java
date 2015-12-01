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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.PublicKeyWrapper;

/**
 * CryptoToken management operations that require authorization and/or security events audit logging.
 * 
 * @version $Id$
 */
public interface CryptoTokenManagementSession {
    
    /** Indicate that we would like to keep the current auto-activation PIN (if present) when save a CryptoToken. */
    public final String KEEP_AUTO_ACTIVATION_PIN = "keepAutoActivationPin";

    /** @return a list of IDs for CryptoTokens that the caller is authorized to view */
    List<Integer> getCryptoTokenIds(AuthenticationToken authenticationToken);

    /** Requests activation of the referenced CryptoToken. */
    void activate(AuthenticationToken authenticationToken, int cryptoTokenId, char[] authenticationCode)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /** Requests deactivation of the referenced CryptoToken. */
    void deactivate(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /**
     * Remove CryptoToken with the specified ID. If this CryptoToken is backed by an HSM only the reference to the
     * PKCS#11 slot will be removed not the actual key material. If the crypto token with the given id does not exists, nothing happens.
     * @param cryptoTokenId the id of the crypto token that should be removed
     */
    void deleteCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /** @return true if the CryptoToken with the specified ID has been activated. */
    boolean isCryptoTokenStatusActive(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /**
     * Creates a crypto token with a known ID. Note that using an already existing ID will lead to an error at a later state. 
     * 
     * @param authenticationToken an authentication token
     * @param tokenName the name of the token
     * @param cryptoTokenId a known and unused ID value. 
     * @param className the class name of the crypto token
     * @param properties a properties file containing implementation specific values
     * @param data the keystore data. If null a new, empty keystore will be created
     * @param authenticationCode the authentication code to the slot. Will not activate the slot if offline
     *
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenNameInUseException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws NoSuchSlotException if no PKCS#11 slot as defined by the label in properties could be found
     */
     void createCryptoToken(AuthenticationToken authenticationToken, String tokenName, Integer cryptoTokenId, String className, Properties properties,
            byte[] data, char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenNameInUseException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, NoSuchSlotException;
    
    /**
     * Create a crypto token. This method will generate its own ID. 
     * 
     * @param authenticationToken an authentication token
     * @param tokenName the name of the token
     * @param className the class name of the crypto token
     * @param properties a properties file containing implementation specific values
     * @param data  the keystore data. If null a new, empty keystore will be created
     * @param authenticationCode authenticationCode the authentication code to the slot
     * @return the ID of a newly persisted CryptoToken from the supplied parameters.
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenNameInUseException
     * @throws NoSuchSlotException if no PKCS#11 slot as defined by the label in properties could be found
     */
    int createCryptoToken(AuthenticationToken authenticationToken, String tokenName, String className, Properties properties, byte[] data,
            char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, NoSuchSlotException;

   
    /**
     * Update the CryptoToken with the specified ID. The authentication code can be omitted (null) if auto-activation is used. 
     * 
     * @param authenticationToken
     * @param cryptoTokenId
     * @param tokenName
     * @param properties
     * @param authenticationCode
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenNameInUseException
     * @throws NoSuchSlotException if no such slot as defined in properties could be found
     */
    void saveCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId, String tokenName, Properties properties,
            char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            CryptoTokenNameInUseException, NoSuchSlotException;

    /**
     * Changes the name and key placeholders of a CryptoToken. Doesn't de-activate the crypto token,
     * and can't be used to change any other properties (e.g. PKCS#11 slot etc.) or the authentication code.
     *
     * @param authenticationToken
     * @param cryptoTokenId Id of the existing crypto token
     * @param newName New name of the crypto token.
     * @param newPlaceholders New key placeholders, in the same format as they are stored in the crypto token properties.
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenNameInUseException If the new name is already in use.
     */
    void saveCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId, String newName, String newPlaceholders) throws AuthorizationDeniedException, CryptoTokenNameInUseException;
    
    /** @return value object with non-sensitive information about the CryptoToken for UI use or similar, or null if token does not exist. */
    CryptoTokenInfo getCryptoTokenInfo(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /** @return List value objects with non-sensitive information about authorized CryptoToken for UI use or similar. Returns empty list if no tokens exist. */
    List<CryptoTokenInfo> getCryptoTokenInfos(AuthenticationToken authenticationToken);

    /** @return the cryptoTokenId from the more user friendly name. Return null of there is no such CryptoToken. */
    Integer getIdFromName(String cryptoTokenName);

    /** @return a List of all the key pair aliases present in the specified CryptoToken. */
    List<String> getKeyPairAliases(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    /**
     * Generate a new key pair in the specified CryptoToken with the requested alias and key specification.
     * 
     * @param keySpecification should be in the form "RSAnnnn", "DSAnnnn" or an known EC curve name.
     * 
     * @throws CryptoTokenOfflineException if the CryptoToken is unavailable or inactive.
     * @throws InvalidKeyException if key generation failed.
     * @throws InvalidAlgorithmParameterException if the keySpecification is not available for this CryptoToken.
     */
    void createKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias, String keySpecification)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Generate a new key pair in the specified CryptoToken with the requested alias using the key specification from
     * another key in the same CryptoToken.
     * 
     * @see #createKeyPair(AuthenticationToken, int, String, String)
     */
    void createKeyPairWithSameKeySpec(final AuthenticationToken authenticationToken, final int cryptoTokenId, String currentSignKeyAlias, String nextSignKeyAlias)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Generates a new key pair and deletes the placeholder.
     * 
     * @see #createKeyPair(AuthenticationToken, int, String, String)
     */
    void createKeyPairFromTemplate(AuthenticationToken authenticationToken, int cryptoTokenId, String alias, String keySpecification)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException;

    /** @throws InvalidKeyException if the CryptoToken is available, but the key test failed */
    void testKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException;

    /** @throws InvalidKeyException if the CryptoToken was active, but the key pair removal failed. */
    void removeKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException;

    /** @throws InvalidKeyException if the key alias placeholder didn't exist. */
    void removeKeyPairPlaceholder(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, InvalidKeyException;

    /** @return list of information about all key pairs in the specified CryptoToken, but no references to the actual keys. */
    List<KeyPairInfo> getKeyPairInfos(AuthenticationToken admin, int cryptoTokenId) throws CryptoTokenOfflineException, AuthorizationDeniedException;

    /** @return information about a key pair with the the specified alias in the CryptoToken, but no references to the actual keys. null if alias does not exist. */
    KeyPairInfo getKeyPairInfo(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws CryptoTokenOfflineException, AuthorizationDeniedException;

    /** @return the public key of the key pair with the the specified alias in the CryptoToken. */
    PublicKeyWrapper getPublicKey(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    /**
     * Set the auto-activation PIN for a CryptoToken.
     * For soft CryptoTokens this will change the pin of the underlying soft keystore as well.
     * For PKCS#11 CryptoTokens this will only modify the auto-activation setting.
     * @param authenticationToken must be authorized to modify the CryptoToken
     * @param cryptoTokenId is the CryptoToken to operate on
     * @param currentAuthenticationCode is the pin that can currently be used to auto-activate (or manually active it if no auto-activation is used) this CryptoToken
     * @param newAuthenticationCode is the new pin to use or null to remove the current auto-activation pin
     * @param updateOnly if true, will only modify the auto-activation setting if already present. Soft CryptoTokens will still have a password change.
     * @return true if the CryptoToken is auto-activated after call
     */
    boolean updatePin(AuthenticationToken authenticationToken, Integer cryptoTokenId, char[] currentAuthenticationCode, char[] newAuthenticationCode,
            boolean updateOnly) throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException;

    /**
     * Returns true if the alias is in use by the crypto token
     * 
     * @param cryptoTokenId id of the crypto token
     * @param alias the alias in question
     * @return true if the alias is in use.
     */
    boolean isAliasUsedInCryptoToken(int cryptoTokenId, String alias);


}
