/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng.provider;

import java.security.PublicKey;

/**
 * Holder for a wrapped key-pair.
 *
 */
public class GeneratedKeyData {
    
    private final byte[] wrappedPrivateKey;
    private final PublicKey publicKey;

    public GeneratedKeyData(byte[] wrappedPrivateKey, PublicKey publicKey) {
        this.wrappedPrivateKey = wrappedPrivateKey;
        this.publicKey = publicKey;
    }

    public byte[] getWrappedPrivateKey() {
        return wrappedPrivateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
}
