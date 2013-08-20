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

import org.cesecore.authentication.tokens.AuthenticationToken;

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

    /** @return value object with non-sensitive information about the CryptoToken for UI use or similar. */
    CryptoTokenInfo getCryptoTokenInfo(int cryptoTokenId);

    /**
     * Checks if a crypto token is active. 
     * 
     * @param cryptoTokenId the ID of the crypto token
     * @return true of it is active.
     */
    boolean isCryptoTokenStatusActive(int cryptoTokenId);

    /**
     * Some changes were made to the crypto token format within 6.0.x. This method ensures that all crypto tokens are scanned on startup
     * and checked to see if they're in the correct format. 
     * 
     * @param authenticationToken an authentication token to authorize this action
     * 
     * @deprecated Remove this method and all references to it before 6.0.0 is released. 
     */
    @Deprecated
    void adhocUpgradeWithin6_0_x(AuthenticationToken authenticationToken);
}
