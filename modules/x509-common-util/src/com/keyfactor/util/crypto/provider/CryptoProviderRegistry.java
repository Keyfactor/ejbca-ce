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
package com.keyfactor.util.crypto.provider;

import java.util.HashSet;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * Provides a registry to read all externally defined crypto providers
 */
public enum CryptoProviderRegistry {
    INSTANCE;
    
    private Set<CryptoProvider> cryptoProviders;
    
    private CryptoProviderRegistry() {
        cryptoProviders = new HashSet<>();
        for(CryptoProvider cryptoProvider : ServiceLoader.load(CryptoProvider.class)) {
            cryptoProviders.add(cryptoProvider);
        }
    }
    
    public Set<CryptoProvider> getCryptoProviders() {
        return cryptoProviders;
    }
    
}
