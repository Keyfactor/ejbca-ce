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
package org.ejbca.core.protocol.ws.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import org.bouncycastle.util.Properties;
import org.cesecore.certificates.certificate.CertificateConstants;

import com.keyfactor.util.Base64;


/**
 * Class used to generate a java.security.KeyStore from a 
 * org.ejbca.core.protocol.ws.common.KeyStore
 * 
 */
public class KeyStoreHelper {

    /**
     * Retrieves the keystore from the encoded data.
     *
     * @param keystoreData byte array
     * @param type         "PKCS12" or "JKS"
     * @param password     to lock the keystore
     * @return the loaded and unlocked keystore.
     * @throws CertificateException     if any of the certificates in the keystore could not be loaded
     * @throws IOException              if there is an I/O or format problem with the keystore data, if a password is required but not given, or if the given password was incorrect
     * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the keystore cannot be found
     * @throws NoSuchProviderException  if the specified provider is not registered in the security provider list
     * @throws KeyStoreException        if a KeyStoreSpi implementation for the specified type is not available from the specified provider
     */
    public static java.security.KeyStore getKeyStore(byte[] keystoreData, String type, String password)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, NoSuchProviderException {
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(keystoreData))) {
            Properties.setThreadOverride(CertificateConstants.ENABLE_UNSAFE_RSA_KEYS, true);
            java.security.KeyStore ks = type.equalsIgnoreCase("JKS") ? java.security.KeyStore.getInstance("JKS")
                    : java.security.KeyStore.getInstance(type, "BC");
            ks.load(bais, password.toCharArray());
            return ks;
        } finally {
            Properties.removeThreadOverride(CertificateConstants.ENABLE_UNSAFE_RSA_KEYS);
        }
    }
}
