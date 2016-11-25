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
package org.cesecore.keys.token;

/**
 * @version $Id$
 *
 */
public interface CryptoTokenSession {

    /** @return true if the specified name is already in use by another CryptoToken (checks the database, not the cache) */
    boolean isCryptoTokenNameUsed(String cryptoTokenName);
    
    /** @return the full class name (including package names) for a CryptoToken type */
    public String getClassNameForType(String tokenType);

    /** @return the name of the given crypto token, or null if it doesn't exist */
    String getCryptoTokenName(int cryptoTokenId);
}
