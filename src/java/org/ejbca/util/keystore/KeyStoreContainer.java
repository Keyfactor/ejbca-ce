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
     * @return
     * @throws Exception 
     */
    byte[] delete(String alias) throws Exception;

    /**
     * @param string
     * @throws Exception
     */
    void generateCertReq(String string) throws Exception;

    /**
     * @param string
     * @throws Exception
     */
    void installCertificate(String string) throws Exception;

    /**
     * @param stream
     * @param stream2
     * @param string
     * @throws Exception
     */
    void decrypt(InputStream stream, OutputStream stream2, String string) throws Exception;

    /**
     * @param stream
     * @param stream2
     * @param string
     * @throws Exception
     */
    void encrypt(InputStream stream, OutputStream stream2, String string) throws Exception;

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
}
