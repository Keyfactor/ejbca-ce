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

/**
 * A PKCS#11 object.
 *
 * @version $Id$
 */
public class NJI11Object {
    private final long object;
    private final CryptokiDevice.Slot slot;

    protected NJI11Object(long object, CryptokiDevice.Slot slot) {
        this.object = object;
        this.slot = slot;
    }

    protected long getObject() {
        return object;
    }
    
    protected CryptokiDevice.Slot getSlot() {
        return slot;
    }
}
