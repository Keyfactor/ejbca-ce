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

import java.security.PrivateKey;

import javax.ejb.Remote;

import org.cesecore.keys.util.PublicKeyWrapper;

/**
 * Bridge for local EJB calls that we only want to expose to in test deployments.
 * 
 * @version $Id$
 */
@Remote
public interface CryptoTokenManagementProxySessionRemote {

    /** @see CryptoTokenManagementSessionLocal#getCryptoToken(int) */
    CryptoToken getCryptoToken(int cryptoTokenId);

    boolean isCryptoTokenNameUsed(final String cryptoTokenName);

    PublicKeyWrapper getPublicKey(int cryptoTokenId, String alias) throws CryptoTokenOfflineException;

    PrivateKey getPrivateKey(int cryptoTokenId, String alias) throws CryptoTokenOfflineException;
    
    String getSignProviderName(int cryptoTokenId);
    
    void flushCache();
}
