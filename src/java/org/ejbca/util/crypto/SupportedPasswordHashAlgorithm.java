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
package org.ejbca.util.crypto;

/**
 * Simple enum to cover the supported password hash algorithms
 * 
 * @version $Id$
 *
 */
public enum SupportedPasswordHashAlgorithm {
    SHA1_OLD("SHA1 without salt"), SHA1_BCRYPT("SHA1 using BCrypt");
    
    private String name;
    
    private SupportedPasswordHashAlgorithm(String name) {
        this.name = name;
    }
    
    @Override
    public String toString() {
        return name;
    }
}
