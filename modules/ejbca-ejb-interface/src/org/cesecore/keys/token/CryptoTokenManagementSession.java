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
import java.security.PublicKey;
import java.util.List;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

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
     * PKCS#11 slot will be removed not the actual key material.
     */
    void deleteCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /** @return true if the CryptoToken with the specified ID has been activated. */
    boolean isCryptoTokenStatusActive(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /** @return the ID of a newly persisted CryptoToken from the supplied parameters. */
    int createCryptoToken(AuthenticationToken authenticationToken, String tokenName, String className, Properties properties, byte[] data,
            char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /** Update the CryptoToken with the specified ID. The authentication code can be omitted (null) if auto-activation is used. */
    void saveCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId, String tokenName, Properties properties,
            char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /** @return value object with non-sensitive information about the CryptoToken for UI use or similar. */
    CryptoTokenInfo getCryptoTokenInfo(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException;

    /** @return List value objects with non-sensitive information about authorized CryptoToken for UI use or similar. */
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

    /** @throws InvalidKeyException if the CryptoToken is available, but the key test failed */
    void testKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException;

    /** @throws InvalidKeyException if the CryptoToken was active, but the key pair removal failed. */
    void removeKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException;

    /** @return list of information about all key pairs in the specified CryptoToken, but no references to the actual keys. */
    List<KeyPairInfo> getKeyPairInfos(AuthenticationToken admin, int cryptoTokenId) throws CryptoTokenOfflineException, AuthorizationDeniedException;

    /** @return information about a key pair with the the specified alias in the CryptoToken, but no references to the actual keys. null if alias does not exist. */
    KeyPairInfo getKeyPairInfo(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws CryptoTokenOfflineException, AuthorizationDeniedException;

    /** @return the public key of the key pair with the the specified alias in the CryptoToken. */
    PublicKey getPublicKey(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException;
}
