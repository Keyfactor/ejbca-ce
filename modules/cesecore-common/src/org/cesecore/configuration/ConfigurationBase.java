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

package org.cesecore.configuration;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.StringTools;

import com.keyfactor.util.string.StringConfigurationCache;

/**
 *
 */
public abstract class ConfigurationBase extends UpgradeableDataHashMap {

    private static final long serialVersionUID = 4886872276324915327L;

    public static final float LATEST_VERSION = 3f;
    
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public abstract void upgrade();
    
    public abstract String getConfigurationId();

    /**
     * Allows the implementing class to have dynamically configured custom classes to be serialized.
     * 
     * @return a set of class or package names.
     */
    public Set<String> getCustomClassesWhitelist() {
        return new HashSet<>();
    }

    /**
     * Allows the implementing class to have dynamically configured custom classes to be serialized.
     * 
     * @param whitelist a set of class or package names.
     */
    public void setCustomClassesWhitelist(Set<String> whitelist) {
        
    }
    
    /** gets an encrypted value from the input string, typically a password, that should be is stored encrypted in the database 
     * @param value the string to encrypt
     * @return encrypted form of value 
     */
    public String getEncryptedValue(String value) {
        char[] encryptionKey = StringConfigurationCache.INSTANCE.getEncryptionKey();
        return StringTools.pbeEncryptStringWithSha256Aes192(value, encryptionKey, StringConfigurationCache.INSTANCE.useLegacyEncryption());
    }
    /** gets a a decrypted value from the (encrypted) input string, typically a password, that was stored encrypted in the database 
     * @param value the string to decrypt
     * @return decrypted form of value 
     */
    public String getDecryptedValue(String value) {
        return StringTools.passwordDecryption(value, this.getClass().getSimpleName());
    }

    public void filterDiffMapForLogging(Map<Object,Object> diff) {
        // Do nothing
    }

}
