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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Session bean for managing operations on crypto tokens that are sensitive, i.e. operations that needs to be audited. This session bean duplicates
 * interfaces from the stand alone beans CryptoTokenFactory and CryptoToken. In a JEE environment this session bean is the preferred way to use these
 * methods that produces an audit trail
 * 
 * See {@link https://wiki.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Key_Management}
 * 
 * Based on CESeCore version:
 *      CryptoTokenSession.java 558 2011-03-15 13:11:28Z tomas
 * 
 * @version $Id$
 * 
 */
public interface CryptoTokenSession {

    /**
     * Creates a crypto token, either it can be a brand new crypto token, or a persisted crypto token that is re-initialized.
     * 
     * @param admin the admin performing the token
     * @param classname
     *            the full classname of the crypto token implementation class
     * @param properties
     *            properties passed to the init method of the CryptoToken
     * @param data
     *            byte data passed to the init method of the CryptoToken
     * @param id
     *            id passed to the init method of the CryptoToken
     */
    CryptoToken createCryptoToken(final AuthenticationToken admin, final String classname, final Properties properties, final byte[] data,
            final int id);

    /**
     * Deletes an entry in the crypto token
     * 
     * @param admin the admin performing the token
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
    CryptoToken deleteEntry(final AuthenticationToken admin, CryptoToken token, char[] authenticationcode, String alias) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException;

    /**
     * Generates a key pair (asymmetric keys) in the crypto token.
     * 
     * @param admin the admin performing the token
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param keySpec
     *            all decimal digits RSA key length, otherwise name of ECC curve or DSA key using syntax DSAnnnn
     * @param alias
     *            the name of the key pair in the crypto token
     */
    CryptoToken generateKeyPair(final AuthenticationToken admin, final CryptoToken token, final char[] authenticationcode, final String keySpec,
            final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, KeyStoreException, CertificateException, IOException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException;

    /**
     * Generates a key pair (asymmetric keys) in the crypto token.
     * 
     * @param admin the admin performing the token
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param template
     *            PublicKey serving as template for the type of key pair that will be generated, a key of the same type will be generated, if
     *            supported
     * @param alias
     *            the name of the key pair in the crypto token
     */
    CryptoToken generateKeyPair(final AuthenticationToken admin, final CryptoToken token, final char[] authenticationcode, final PublicKey template,
            final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, KeyStoreException, CertificateException, IOException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException;

    /**
     * Generates a symmetric key.
     * 
     * @param admin the admin performing the token
     * @param authenticationcode
     *            Crypto token authentication code/pin
     * @param algorithm
     *            symmetric algorithm specified in http://download.oracle.com/javase/1.5.0/docs/api/index.html, suggest AES, DESede or DES
     * @param keysize
     *            keysize of symmetric key, suggest 128 or 256 for AES, 64 for 168 for DESede and 64 for DES
     * @param alias
     *            the alias the key will get in the keystore
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    CryptoToken generateKey(final AuthenticationToken admin, final CryptoToken token, final char[] authenticationcode, final String algorithm,
            final int keysize, final String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidKeyException, InvalidAlgorithmParameterException,
            SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException;

}
