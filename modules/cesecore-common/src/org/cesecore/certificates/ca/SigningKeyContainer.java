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

package org.cesecore.certificates.ca;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * POJO containing two sets of public/private keys, as well as their respective provider identifiers, to alleviate performing signatures using multiple key pairs. 
 */

public class SigningKeyContainer {
    private final PublicKey primaryPublicKey;
    private final PrivateKey primaryPrivateKey;
    private final PublicKey alternativePublicKey;
    private final PrivateKey alternativePrivateKey;
    private final String primaryProvider;
    private final String alternativeProvider;

    public SigningKeyContainer(final PublicKey primaryPublicKey, final PrivateKey primaryPrivateKey, final String primaryProvider) {
        this.primaryPublicKey = primaryPublicKey;
        this.primaryPrivateKey = primaryPrivateKey;
        this.primaryProvider = primaryProvider;
        this.alternativePublicKey = null;
        this.alternativePrivateKey = null;
        this.alternativeProvider = null;
    }
    
    public SigningKeyContainer(final PublicKey primaryPublicKey, final PrivateKey primaryPrivateKey, final String primaryProvider,
            final PublicKey alternativePublicKey, final PrivateKey alternativePrivateKey, final String alternativeProvider) {
        this.primaryPublicKey = primaryPublicKey;
        this.primaryPrivateKey = primaryPrivateKey;
        this.primaryProvider = primaryProvider;
        this.alternativePublicKey = alternativePublicKey;
        this.alternativePrivateKey = alternativePrivateKey;
        this.alternativeProvider = alternativeProvider;
    }

    public PublicKey getPrimaryPublicKey() {
        return primaryPublicKey;
    }

    public PrivateKey getPrimaryPrivateKey() {
        return primaryPrivateKey;
    }

    public PublicKey getAlternativePublicKey() {
        return alternativePublicKey;
    }


    public PrivateKey getAlternativePrivateKey() {
        return alternativePrivateKey;
    }

    public String getPrimaryProvider() {
        return primaryProvider;
    }

    public String getAlternativeProvider() {
        return alternativeProvider;
    }
}