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

import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;

/**
 * @version $Id$
 */
public class KeyStoreContainerFactory {

    /**
     * @param keyStoreType
     * @param providerClassName
     * @param encryptProviderClassName
     * @param storeID
     * @param slotLabelType the slot label type
     * @param attributesFile
     * @param pp
     * @return
     * @throws Exception
     */
    public static KeyStoreContainer getInstance(final String keyStoreType, final String providerClassName, final String encryptProviderClassName,
            final String storeID, final Pkcs11SlotLabelType slotLabelType, final String attributesFile, final KeyStore.ProtectionParameter pp,
            final String privateKeyLabel) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        if (isP11(keyStoreType)) {
            return KeyStoreContainerP11.getInstance(storeID, slotLabelType, providerClassName, attributesFile, pp, privateKeyLabel);
        }
        return KeyStoreContainerJCE.getInstance(keyStoreType, providerClassName, encryptProviderClassName, storeID != null ? storeID.getBytes()
                : null);
    }
    public static KeyStoreContainer getInstance(final String keyStoreType,
            final String providerClassName,
            final String encryptProviderClassName,
            final String storeID,
            final Pkcs11SlotLabelType slotLabelType,
            final String attributesFile,
            final KeyStore.ProtectionParameter pp) throws Exception {
        return getInstance(keyStoreType, providerClassName, encryptProviderClassName, storeID, slotLabelType, attributesFile, pp, null);
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
