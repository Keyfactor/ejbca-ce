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

import com.keyfactor.util.keys.token.CryptoToken;

/**
 *
 */
public interface CryptoTokenSession {

    /** @return true if the specified name is already in use by another CryptoToken (checks the database, not the cache) */
    boolean isCryptoTokenNameUsed(String cryptoTokenName);
    
    /** @return the full class name (including package names) for a CryptoToken type */
    String getClassNameForType(String tokenType);

    /** @return the name of the given crypto token, or null if it doesn't exist */
    String getCryptoTokenName(int cryptoTokenId);
    
    /** @return the specified CryptoToken or null if it does not exis.
     * Throws RuntimeException if allow.nonexisting.slot=false (default) and a PKCS#11 slot does not exist. */
    CryptoToken getCryptoToken(int cryptoTokenId);

    /** Add the specified CryptoToken to the database if it does not exist, or edit the CryptoToken if it exists.
     * Has an optimization that if the CryptoToken exists and is not changed from what already exists in the database, no change is made.
     * This optimization prevents other cluster nodes to reload the crypto token (can be a PKCS#11 token) when there is no need.
     * @param cryptoToken the crypto token data to add or edit
     * @return the crypto token ID used to store it. */
    int mergeCryptoToken(CryptoToken cryptoToken) throws CryptoTokenNameInUseException;
}
