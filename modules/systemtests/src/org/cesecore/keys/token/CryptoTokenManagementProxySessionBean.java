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

import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.PublicKeyWrapper;

/**
 * @see CryptoTokenManagementProxySessionRemote
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CryptoTokenManagementProxySessionRemote")
public class CryptoTokenManagementProxySessionBean implements CryptoTokenManagementProxySessionRemote {

    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;

    @Override
    public CryptoToken getCryptoToken(int cryptoTokenId) {
        return cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
    }

    @Override
    public boolean isCryptoTokenNameUsed(String cryptoTokenName) {
        return cryptoTokenSession.isCryptoTokenNameUsed(cryptoTokenName);
    }
    
    @Override
    public PublicKeyWrapper getPublicKey(int cryptoTokenId, String alias) throws CryptoTokenOfflineException {
        CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
        return new PublicKeyWrapper(cryptoToken.getPublicKey(alias));
    }
    
    @Override
    public PrivateKey getPrivateKey(int cryptoTokenId, String alias) throws CryptoTokenOfflineException {
        CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
        return cryptoToken.getPrivateKey(alias);
    }
    
    @Override
    public String getSignProviderName(int cryptoTokenId) {
        CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
        return cryptoToken.getSignProviderName();
    }

    @Override
    public void flushCache() {
       cryptoTokenSession.flushCache();
        
    }
}
