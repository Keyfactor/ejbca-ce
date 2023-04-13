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
package org.cesecore.keys.token;

import javax.ejb.Local;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * @see CryptoTokenManagementSession
 * @version $Id$
 */
@Local
public interface CryptoTokenManagementSessionLocal extends CryptoTokenManagementSession {

    /**
     * This method can be used whenever the authorization is implied. E.g. the caller had access
     * to an object that references this CryptoToken and that reference cannot change.
     * 
     * @return a reference to the cached and potentially active CryptoToken object.
     */
    CryptoToken getCryptoToken(int cryptoTokenId);

    /**
     * Get non-sensitive information about a crypto token. This information can be displayed
     * in the GUI or similar.
     *
     * @param cryptoTokenId the ID of the crypto token to get information for.
     * @return information about the crypto token or <code>null</code> if no crypto token
     * with the given ID was found.
     */
    CryptoTokenInfo getCryptoTokenInfo(int cryptoTokenId);

    /**
     * Checks if a crypto token is present and active. 
     * 
     * @param cryptoTokenId the ID of the crypto token
     * @return true if it exists, is present and is active.
     */
    boolean isCryptoTokenStatusActive(int cryptoTokenId);
}
