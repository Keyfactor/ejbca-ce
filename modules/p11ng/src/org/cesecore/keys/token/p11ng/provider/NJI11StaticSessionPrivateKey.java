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
 * A PrivateKey with a reserved session.
 *
 * @version $Id$
 */
public class NJI11StaticSessionPrivateKey extends NJI11Object implements Key, PrivateKey {

    private static final long serialVersionUID = -1393340200834353434L;

    private final NJI11Session session;
    private final boolean removalOnRelease;

    public NJI11StaticSessionPrivateKey(NJI11Session session, long object, CryptokiDevice.Slot slot, boolean removalOnRelease) {
        super(object, slot);
        this.session = session;
        this.removalOnRelease = removalOnRelease;
    }
    
    @Override
    public String getAlgorithm() {
        return "RSA";
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
