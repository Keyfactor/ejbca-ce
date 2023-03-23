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

/**
 * A PKCS#11 object.
 *
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
