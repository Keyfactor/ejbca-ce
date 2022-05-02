/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.provider;

import java.security.Key;
import javax.crypto.SecretKey;

/**
 * A SecretKey without a session.
 *
 * @version $Id$
 */
public class NJI11ReleasebleSessionSecretKey extends NJI11Object implements Key, SecretKey {
    
    private static final long serialVersionUID = 3458221493061819379L;

    private final String algorithm;
    private final String keySpec;
    
    public NJI11ReleasebleSessionSecretKey(long object, String algorithm, String keySpec, CryptokiDevice.Slot slot) {
        super(object, slot);
        this.algorithm = algorithm;
        this.keySpec = keySpec;
    }
    
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
    
    public String getKeySpec() {
        return keySpec;
    }

}
