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

import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @version $Id$
 * @author primelars
 */
public class KeyStoreContainerFactory {

    /**
     * @param keyStoreType
     * @param providerClassName
     * @param encryptProviderClassName
     * @param storeID
     * @param attributesFile
     * @param pp
     * @return
     * @throws Exception
     */
    public static KeyStoreContainer getInstance(final String keyStoreType,
                                                final String providerClassName,
                                                final String encryptProviderClassName,
                                                final String storeID,
                                                final String attributesFile,
                                                final KeyStore.ProtectionParameter pp,
                                                final String privateKeyLabel) throws Exception {
        Security.addProvider( new BouncyCastleProvider() );
        if ( isP11(keyStoreType) ) {
            final char firstChar = storeID!=null && storeID.length()>0 ? storeID.charAt(0) : '\0';
            final String slotID;
            final boolean isIndex;
            if ( storeID!=null && (firstChar=='i'||firstChar=='I') ) {
                slotID = storeID.substring(1);
                isIndex = true;
            } else {
                slotID = storeID;
                isIndex = false;
            }
            return KeyStoreContainerP11.getInstance( slotID,
                                                     providerClassName,
                                                     isIndex, attributesFile, pp,
                                                     privateKeyLabel);
        }
        return KeyStoreContainerJCE.getInstance( keyStoreType,
                                                 providerClassName,
                                                 encryptProviderClassName,
                                                 storeID!=null ? storeID.getBytes():null);
    }
    public static KeyStoreContainer getInstance(final String keyStoreType,
            final String providerClassName,
            final String encryptProviderClassName,
            final String storeID,
            final String attributesFile,
            final KeyStore.ProtectionParameter pp) throws Exception {
        return getInstance(keyStoreType, providerClassName, encryptProviderClassName, storeID, attributesFile, pp, null);
    }
    /**
     * @param keyStoreType
     * @param providerName
     * @param pp
     * @return
     * @throws Exception
     */
    public static KeyStoreContainer getInstance(final String keyStoreType, final String providerName, KeyStore.ProtectionParameter pp) throws Exception {
        if ( isP11(keyStoreType) ) {
            return KeyStoreContainerP11.getInstance(providerName, pp);
        }
        throw new IllegalArgumentException("This getInstance only available for PKCS#11 providers.");
    }
    private static boolean isP11(String keyStoreType) {
        return keyStoreType.toLowerCase().indexOf(KeyStoreContainer.KEYSTORE_TYPE_PKCS11) >= 0;
    }

}
