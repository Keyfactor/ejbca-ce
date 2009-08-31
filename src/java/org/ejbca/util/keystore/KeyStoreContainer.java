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

package org.ejbca.util.keystore;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;

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
     * @return
     * @throws Exception
     */
    byte[] storeKeyStore() throws Exception;

    /**
     * @param i
     * @param keyEntryName
     * @return
     * @throws Exception 
     */
    byte[] generate(int i, String keyEntryName) throws Exception;

    /**
     * @param alias
     * @return keystore identifier
     * @throws Exception 
     */
    byte[] delete(String alias) throws Exception;

    /**
     * @param oldAlias
     * @param newAlias
     * @return keystore identifier
     * @throws Exception
     */
    byte[] renameAlias( String oldAlias, String newAlias ) throws Exception;

    /**
     * @param string alias for the key to be used
     * @param dn the DN to be used. If null the 'CN=alias' will be used
     * @throws Exception
     */
    void generateCertReq(String string, String dn) throws Exception;

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
     * @throws Exception
     */
    void encrypt(InputStream in, OutputStream out, String alias) throws Exception;

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
     * @param alias
     * @return
     * @throws Exception
     */
    Key getKey(String alias) throws Exception;

    /**
     * @return
     */
    KeyStore getKeyStore();

    /**
     * @return
     */
    String getProviderName();

    /**
     * @param string
     * @param keyEntryName
     * @return
     * @throws Exception
     */
    byte[] generate(String string, String keyEntryName) throws Exception;

    /**
     * @param name
     * @param keyEntryName
     * @return
     * @throws Exception
     */
    public byte[] generateEC( final String name, final String keyEntryName) throws Exception;

    /**
     * @param name
     * @param keyEntryName
     * @return
     * @throws Exception
     */
    public byte[] generateDSA( final int keysize, final String keyEntryName) throws Exception;
}
