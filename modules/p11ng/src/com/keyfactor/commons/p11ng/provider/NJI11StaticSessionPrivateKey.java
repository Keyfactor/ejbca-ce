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

import java.security.Key;
import java.security.PrivateKey;

/**
 * A PrivateKey with a reserved session.
 *
 */
public class NJI11StaticSessionPrivateKey extends NJI11Object implements Key, PrivateKey {

    private static final long serialVersionUID = -1393340200834353434L;

    private final NJI11Session session;
    private final String algorithm;
    private final boolean removalOnRelease;

    public NJI11StaticSessionPrivateKey(NJI11Session session, long object, String algorithm, CryptokiDevice.Slot slot, boolean removalOnRelease) {
        super(object, slot);
        this.session = session;
        this.algorithm = algorithm;
        this.removalOnRelease = removalOnRelease;
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

    protected NJI11Session getSession() {
        return session;
    }

    public boolean isRemovalOnRelease() {
        return removalOnRelease;
    }

}
