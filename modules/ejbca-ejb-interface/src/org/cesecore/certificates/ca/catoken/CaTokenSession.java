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
package org.cesecore.certificates.ca.catoken;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;

/**
 * Bean for operations on a CA token that requires audit.
 * 
 * @version $Id: CaTokenSession.java 756 2011-05-09 09:25:42Z tomas $
 */
public interface CaTokenSession {

    /**
     * Deactivates a CA token so that the CA can not sign or encrypt with it.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be deactivated
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws IllegalCryptoTokenException
     */
    void deactivateCAToken(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException,
            IllegalCryptoTokenException;

    /**
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be activated
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * 
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws IllegalCryptoTokenException
     */
    void activateCAToken(final AuthenticationToken admin, final int caid, final char[] authenticationcode) throws CADoesntExistsException,
            AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, IllegalCryptoTokenException;

    /**
     * Method that generates the keys that will be used by the CAToken. The method can be used to generate keys for an initial CA token or to renew
     * Certificate signing keys. If setstatustowaiting is true and you generate new keys, the new keys will be available as
     * CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN. If setstatustowaiting is false and you generate new keys, the new keys will be available as
     * CryptoTokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            the password used to encrypt the keystore, later needed to activate CA Token
     * @param renew
     *            flag indicating if the keys are renewed instead of created fresh. Renewing keys does not create new encryption keys, since this
     *            would make it impossible to decrypt old stuff.
     * @param activate
     *            flag indicating if the new keys should be activated immediately or or they should be added as "next" signing key. Using true here
     *            makes it possible to generate certificate renewal requests for external CAs still using the old keys until the response is received.
     * 
     * @throws CryptoTokenAuthenticationFailedException
     * @throws IOException
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * 
     */
    void generateKeys(AuthenticationToken admin, final int caid, final char[] authenticationcode, final boolean renew, final boolean activate)
            throws CADoesntExistsException, AuthorizationDeniedException, InvalidKeyException, CryptoTokenAuthenticationFailedException,
            CryptoTokenOfflineException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException,
            InvalidAlgorithmParameterException, SignatureException, IllegalCryptoTokenException, IOException;

    /**
     * Activates the next signing key, if a new signing key has previously been generated and defined as the "next" signing key.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * 
     * @throws IOException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * @throws SignatureException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws InvalidKeyException
     * 
     */
    void activateNextSignKey(AuthenticationToken admin, final int caid, char[] authenticationcode) throws CADoesntExistsException,
            AuthorizationDeniedException, InvalidKeyException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException,
            KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException,
            IllegalCryptoTokenException, IOException;

    /** Changes or adds crypto token properties.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param key property key to set/change
     * @param value property value to set/change
     * 
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws IllegalCryptoTokenException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     */
	public void setTokenProperty(final AuthenticationToken admin, final int caid, final char[] authenticationcode, final String key, final String value) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /**
     * Deletes an entry in the crypto token
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param alias
     *            is a reference to the entry in the token that should be deleted.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    void deleteTokenEntry(final AuthenticationToken admin, final int caid, char[] authenticationcode, String alias) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException;

    /**
     * Generates a key pair (asymmetric keys) in the crypto token.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param keySpec
     *            all decimal digits RSA key length, otherwise name of ECC curve or DSA key using syntax DSAnnnn
     * @param alias
     *            the name of the key pair in the crypto token
     */
    void generateKeyPair(final AuthenticationToken admin, final int caid, final char[] authenticationcode, final String keySpec, final String alias) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, IllegalCryptoTokenException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, KeyStoreException, CertificateException, IOException;

    /**
     * Generates a key pair (asymmetric keys) in the crypto token.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param template
     *            PublicKey serving as template for the type of key pair that will be generated, a key of the same type will be generated, if
     *            supported
     * @param alias
     *            the name of the key pair in the crypto token
     */
    void generateKeyPair(final AuthenticationToken admin, final int caid, final char[] authenticationcode, final PublicKey template, final String alias) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, IllegalCryptoTokenException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, KeyStoreException, CertificateException, IOException;

    /**
     * Retrieves the public key of a specific alias from a CAs token
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param alias
     *            the name of the key pair in the crypto token
     * @return PublicKey if a key with the specified alias exists, throws CryptoTokenOfflineException if the key does not exist
     * 
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws IllegalCryptoTokenException
     * @throws CryptoTokenOfflineException if the token is not active, or the key does not exist
     * @throws CryptoTokenAuthenticationFailedException
     */
    PublicKey getPublicKey(final AuthenticationToken admin, final int caid, final char[] authenticationcode, final String alias) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /**
     * Retrieves the public key for a specific key usage.
     * A CA token can have many keys, but some keys are associated with specific usages, such as CATokenConstants.CAKEYPURPOSE_CERTSIGN.
     * 
     * @param admin the admin performing the token
     * @param caid
     *            the CA whose token should be operated on
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param keyPurpose
     *            the usage of the key pair in the CA token, one of CATokenConstants.CAKEYPURPOSE_XYZ
     * @return PublicKey if a key with the specified purpose exists, throws CryptoTokenOfflineException if the key does not exist
     * 
     * @throws CADoesntExistsException
     * @throws AuthorizationDeniedException
     * @throws IllegalCryptoTokenException
     * @throws CryptoTokenOfflineException if the token is not active, or the key does not exist
     * @throws CryptoTokenAuthenticationFailedException
     */
    PublicKey getPublicKey(final AuthenticationToken admin, final int caid, final char[] authenticationcode, final int keyPurpose) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

}
