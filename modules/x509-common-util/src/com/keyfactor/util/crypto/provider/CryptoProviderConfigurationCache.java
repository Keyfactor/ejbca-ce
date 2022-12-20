/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.crypto.provider;

/**
 *
 */
public enum CryptoProviderConfigurationCache {
    INSTANCE;
    
    private boolean p11disableHashingSignMechanisms;  
    private boolean useLegacyPkcs12Keystore;    
    private boolean keystoreCacheEnabled;
    private boolean permitExtractablePrivateKeys;
    private boolean keyUnmodifiableAfterGeneration;
    
    private CryptoProviderConfigurationCache() {
        //Set defaults
        useLegacyPkcs12Keystore = false;
        p11disableHashingSignMechanisms = true;
        keystoreCacheEnabled = true;
        permitExtractablePrivateKeys = false;
        keyUnmodifiableAfterGeneration = false;
    }
    
    public boolean isUseLegacyPkcs12Keystore() {
        return useLegacyPkcs12Keystore;
    }

    public void setUseLegacyPkcs12Keystore(boolean useLegacyPkcs12Keystore) {
        this.useLegacyPkcs12Keystore = useLegacyPkcs12Keystore;
    }
    
    /**
     * Disabling of sign mechanisms that are using PKCS#11 to hash the data before signing. 
     * If these mechanisms are disabled then the sun PKCS#11 wrapper will do the hashing before PKCS#11 is called.
     * Default: true (the mechanisms are disabled).
     * 
     * @return true if sign mechanisms that uses PKCS#11 for hashing should be disabled, if no value is defined for pkcs11.disableHashingSignMechanisms default value is true.
     */
    public boolean isP11disableHashingSignMechanisms() {
        return p11disableHashingSignMechanisms;
    }

    public void setP11disableHashingSignMechanisms(boolean p11disableHashingSignMechanisms) {
        this.p11disableHashingSignMechanisms = p11disableHashingSignMechanisms;
    }

    public boolean isKeystoreCacheEnabled() {
        return keystoreCacheEnabled;
    }

    public void setKeystoreCacheEnabled(boolean keystoreCacheEnabled) {
        this.keystoreCacheEnabled = keystoreCacheEnabled;
    }

    /**
     * @return true if it is permitted to use an extractable private key in a HSM.
     */
    public boolean isPermitExtractablePrivateKeys() {
        return permitExtractablePrivateKeys;
    }

    public void setPermitExtractablePrivateKeys(boolean permitExtractablePrivateKeys) {
        this.permitExtractablePrivateKeys = permitExtractablePrivateKeys;
    }

    public boolean isKeyUnmodifiableAfterGeneration() {
        return keyUnmodifiableAfterGeneration;
    }

    public void setKeyUnmodifiableAfterGeneration(boolean keyUnmodifiableAfterGeneration) {
        this.keyUnmodifiableAfterGeneration = keyUnmodifiableAfterGeneration;
    }

}
