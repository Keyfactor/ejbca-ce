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
import java.security.PrivateKey;

/**
 * A PrivateKey without a session.
 *
 * @version $Id$
 */
public class NJI11ReleasebleSessionPrivateKey extends NJI11Object implements Key, PrivateKey {
    
    private static final long serialVersionUID = -1293160515130067674L;

    
    private final String algorithm;
    
    public NJI11ReleasebleSessionPrivateKey(long object, String algorithm, CryptokiDevice.Slot slot) {
        super(object, slot);
        this.algorithm = algorithm;
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

}
