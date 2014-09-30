/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util.keystore;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.spec.AlgorithmParameterSpec;

import org.ejbca.util.CMS;

/**
 * @version $Id$
 * @author primelars
 */
public interface KeyStoreContainer {

    /**
     * 
     */
    public static String KEYSTORE_TYPE_PKCS11 = "pkcs11";

    /**
     * @return In case of soft keystore, the bytes of the encoded keystore. In case of PKCS#11 tokens (HSMs) it returns byte[0].
     * @throws Exception
     */
    byte[] storeKeyStore() throws Exception;

    /**
     * @param alias is a reference to the entry in the KeyStore that should be deleted
     * @return keystore identifier
     * @throws Exception 
     */
    byte[] delete(String alias) throws Exception;

    /**
     * @param oldAlias is the current name
     * @param newAlias si the new name
     * @return keystore identifier
     * @throws Exception
     */
    byte[] renameAlias( String oldAlias, String newAlias ) throws Exception;

    /**
     * @param alias for the key to be used
     * @param dn the DN to be used. If null the 'CN=alias' will be used
     * @param explicitEccParameters false should be default and will use NamedCurve encoding of ECC public keys (IETF recommendation), use true to include all parameters explicitly (ICAO ePassport requirement).
     * @throws Exception
     */
    void generateCertReq(String alias, String dn, boolean explicitEccParameters) throws Exception;

    /**
     * Install certificate chain to key in keystore.
     * @param file name of the file with chain. Starting with the certificate of the key. Ending with the root certificate.
     * @throws Exception
     */
    void installCertificate(String string) throws Exception;

    /**
     * Install trusted root in trust store
     * @param File name of the trusted root.
     * @throws Exception
     */
    void installTrustedRoot(String string) throws Exception;

    /**
     * @param in
     * @param out
     * @param alias
     * @throws Exception
     */
    void decrypt(InputStream in, OutputStream out, String alias) throws Exception;

    /**
     * @param in
     * @param out
     * @param alias
     * @param symmAlgOid the symmetric encryption algorithm to use, for example CMSEnvelopedGenerator.AES128_CBC
     * @throws Exception
     */
    void encrypt(InputStream in, OutputStream out, String alias, String symmAlgOid) throws Exception;

    /**
     * @param in
     * @param out
     * @param alias
     * @throws Exception
     */
    void sign(InputStream in, OutputStream out, String alias) throws Exception;

    /**
     * @param in
     * @param out
     * @param alias
     * @return
     * @throws Exception
     */
    CMS.VerifyResult verify(InputStream in, OutputStream out, String alias) throws Exception;

    /**
     * @param authCode
     */
    void setPassPhraseLoadSave(char[] authCode);

    /**
     * @return
     */
    char[] getPassPhraseGetSetEntry();

    /**
     * @param alias is the name of an entry in the underlying KeyStore
     * @return the Key object
     * @throws Exception
     */
    Key getKey(String alias) throws Exception;

    /**
     * @return a reference to the KeyStore for this container
     */
    KeyStore getKeyStore();

    /**
     * @return the name of the Provider used by this container
     */
    String getProviderName();

    /** Generates keys in the Keystore token.
     * @param keySpec all decimal digits RSA key length, otherwise name of ECC curve or DSA key using syntax DSAnnnn
     * @param keyEntryName
     * @return In case of soft keystore, the bytes of the encoded keystore. In case of PKCS#11 tokens (HSMs) it returns byte[0].
     * @throws Exception
     */
    byte[] generate(final String keySpec, final String keyEntryName) throws Exception;

    /** Generates keys in the Keystore token.
     * @param spec AlgorithmParameterSpec for the KeyPairGenerator. Can be anything like RSAKeyGenParameterSpec, DSAParameterSpec, ECParameterSpec or ECGenParameterSpec. 
     * @param keyEntryName
     * @return In case of soft keystore, the bytes of the encoded keystore. In case of PKCS#11 tokens (HSMs) it returns byte[0].
     * @throws Exception
     */
    byte[] generate( final AlgorithmParameterSpec spec, final String keyEntryName) throws Exception;

}
