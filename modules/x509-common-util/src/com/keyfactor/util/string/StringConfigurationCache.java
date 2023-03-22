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
package com.keyfactor.util.string;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.lang3.ArrayUtils;

import com.keyfactor.util.StringTools;

/**
 *  Singleton configuration holder for String related values, such as forbidden characters. Allows configurations to be registered and retrieved whether 
 *  they're from the static config or database. 
 *
 */
public enum StringConfigurationCache {
    INSTANCE;
    
    public static final int DEFAULT_ENCRYPTION_COUNT = 100;
        
    private static final char[] DEFAULT_FORBIDDEN_CHARACTERS = {'\n', '\r', ';', '!', '\u0000', '%', '`', '?', '$', '~'};  

    private  Set<Character> forbiddenCharacters = null;
    
    private int passwordEncryptionCount;
    
    private char[] encryptionKey;
    
    
    private StringConfigurationCache() {
        forbiddenCharacters = null;
        passwordEncryptionCount = DEFAULT_ENCRYPTION_COUNT;
        encryptionKey = new char[0];
    }
    
    /**
     * Sets the parameter as the set of forbidden characters. If the array is null or empty, the default set will be set. 
     * 
     * @param forbiddenCharacters an array of characters to forbid
     */
    public void setForbiddenCharacters(char[] forbiddenCharacters) {
        if (forbiddenCharacters == null) {
            this.forbiddenCharacters = new HashSet<>(Arrays.asList(ArrayUtils.toObject(DEFAULT_FORBIDDEN_CHARACTERS)));
        } else {
            this.forbiddenCharacters = new HashSet<>(Arrays.asList(ArrayUtils.toObject(forbiddenCharacters)));
        }
    }
    
    /**
     * @return the list of forbidden characters. If none has been set for any reason, the default will be returned. 
     */
    public char[] getForbiddenCharacters() {
        if (forbiddenCharacters == null) {
            return DEFAULT_FORBIDDEN_CHARACTERS;
        } else {
            return ArrayUtils.toPrimitive(forbiddenCharacters.toArray(new Character[forbiddenCharacters.size()]));
        }
    }

    public int getPasswordEncryptionCount() {
        return passwordEncryptionCount;
    }

    public void setPasswordEncryptionCount(int passwordEncryptionCount) {
        this.passwordEncryptionCount = passwordEncryptionCount;
    }

    public char[] getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(char[] encryptionKey) {
        this.encryptionKey = encryptionKey;
    }
    
    /**
     * @return true for systems still configured to use the legacy encryption mode
     */
    public boolean useLegacyEncryption() {
        final String defaultPassword = StringTools.deobfuscate("OBF:1m0r1kmo1ioe1ia01j8z17y41l0q1abo1abm1abg1abe1kyc17ya1j631i5y1ik01kjy1lxf");
        return Objects.deepEquals(defaultPassword.toCharArray(), this.encryptionKey);
    }
}
