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
package org.ejbca.util.string;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang3.ArrayUtils;

/**
 *  Singleton configuration holder for String related values, such as forbidden characters. Allows configurations to be registered and retrieved whether 
 *  they're from the static config or database. 
 *
 */
public enum StringConfigurationCache {
    INSTANCE;
    
    public static final int DEFAULT_ENCRYPTION_COUNT = 100;
        
    private static final char[] defaultForbiddenCharacters = {'\n', '\r', ';', '!', '\u0000', '%', '`', '?', '$', '~'};  

    private static Set<Character> forbiddenCharacters = new HashSet<>();
    
    private static int passwordEncryptionCount = DEFAULT_ENCRYPTION_COUNT;
    
    private static char[] encryptionKey = {}; 
    
    
    /**
     * Sets the parameter as the set of forbidden characters. If the array is null or empty, the default set will be set. 
     * 
     * @param forbiddenCharacters an array of characters to forbid
     */
    public void setForbiddenCharacters(char[] forbiddenCharacters) {
        if (forbiddenCharacters == null || forbiddenCharacters.length == 0) {
            StringConfigurationCache.forbiddenCharacters = new HashSet<>(Arrays.asList(ArrayUtils.toObject(defaultForbiddenCharacters)));
        } else {
            StringConfigurationCache.forbiddenCharacters = new HashSet<>(Arrays.asList(ArrayUtils.toObject(forbiddenCharacters)));
        }
    }
    
    /**
     * @return the list of forbidden characters. If none has been set for any reason, the default will be returned. 
     */
    public char[] getForbiddenCharacters() {
        if (forbiddenCharacters.size() == 0) {
            return defaultForbiddenCharacters;
        } else {
            return ArrayUtils.toPrimitive(forbiddenCharacters.toArray(new Character[forbiddenCharacters.size()]));
        }
    }

    public int getPasswordEncryptionCount() {
        return passwordEncryptionCount;
    }

    public void setPasswordEncryptionCount(int passwordEncryptionCount) {
        StringConfigurationCache.passwordEncryptionCount = passwordEncryptionCount;
    }

    public char[] getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(char[] encryptionKey) {
        StringConfigurationCache.encryptionKey = encryptionKey;
    }
}
