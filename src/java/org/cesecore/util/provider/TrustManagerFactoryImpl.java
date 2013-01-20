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
package org.cesecore.util.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import javax.net.ssl.X509TrustManager;

/**
 * 
 * @version $Id$
 */
abstract class TrustManagerFactoryImpl extends TrustManagerFactorySpi {

    private X509TrustManager trustManager = null;
    private boolean isInitialized = false;

    public TrustManagerFactoryImpl() {
        // empty
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.TrustManagerFactorySpi#engineGetTrustManagers()
     */
    @Override
    protected TrustManager[] engineGetTrustManagers() {
        if (!this.isInitialized) {
            throw new IllegalStateException("TrustManagerFactoryImpl is not initialized");
        }
        return new TrustManager[] { this.trustManager };
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(java.security.KeyStore)
     */
    @Override
    protected void engineInit(KeyStore ks) throws KeyStoreException {
        this.trustManager = getInstance(ks);
        this.isInitialized = true;
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.TrustManagerFactorySpi#engineInit(javax.net.ssl.ManagerFactoryParameters)
     */
    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        this.trustManager = getInstance(spec);
        this.isInitialized = true;
    }

    abstract X509TrustManager getInstance(KeyStore ks) throws KeyStoreException;

    abstract X509TrustManager getInstance(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException;

    public static final class AcceptAll extends TrustManagerFactoryImpl {
        /* (non-Javadoc)
         * @see org.ejbca.util.provider.TrustManagerFactoryImpl#getInstance(java.security.KeyStore)
         */
        @Override
        X509TrustManager getInstance(KeyStore ks) throws KeyStoreException {
            return new X509TrustManagerAcceptAll();
        }

        /* (non-Javadoc)
         * @see org.ejbca.util.provider.TrustManagerFactoryImpl#getInstance(javax.net.ssl.ManagerFactoryParameters)
         */
        @Override
        X509TrustManager getInstance(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
            return new X509TrustManagerAcceptAll();
        }
    }
}
