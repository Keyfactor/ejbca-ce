/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.PKCS11SlotListWrapper;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice.Slot;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;

import java.io.File;
import java.util.HashMap;
import java.util.List;

/**
 * This class wraps C_GetSlotList call to P11 to get information about slots/tokens and their labels
 * 
 * A slot list and token labels for each slot is cached so that C_GetSlotList() only has to be called once and
 * so that C_GetTokenInfo() only has to be called once for each slot. This means that is additional/new slots are created on a token
 * EJBCA has to be restarted.
 */
public class P11NGSlotListWrapper implements PKCS11SlotListWrapper {
    private static final Logger log = Logger.getLogger(P11NGSlotListWrapper.class);

    private final HashMap<Long, char[]> labelMap;
    private final long slotList[];
    private final String fileName;

    public P11NGSlotListWrapper(final String fileName) {
        this.fileName = fileName;
        labelMap = new HashMap<>();
        slotList = C_GetSlotList();
        for (long id : slotList) {
            labelMap.put(id, getTokenLabelLocal(id));
        }
    }

    @Override
    public long[] getSlotList() {
        return slotList;
    }

    @Override
    public char[] getTokenLabel(long slotID) {
        if (log.isTraceEnabled()) {
            log.trace(">getTokenLabel: " + slotID);
        }
        return labelMap.get(slotID);
    }

    private long[] C_GetSlotList() {
        if (log.isTraceEnabled()) {
            log.trace(">C_GetSlotList");
        }
        // Use P11NG to get the list of slots, because we have better control of what we do than trying to use SunP11
        final File lib = new File(fileName);
        final String libDir = lib.getParent();
        final String libName = lib.getName();
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir, true);
        final List<Slot> list = device.getSlots();
        long[] slots = new long[list.size()];
        for (int i = 0; i < list.size(); i++) {
            slots[i] = list.get(i).getId();
        }
        return slots;
    }

    private char[] getTokenLabelLocal(long slotID)  {
        if (log.isTraceEnabled()) {
            log.trace(">getTokenLabelLocal: " + slotID);
        }
        // Use P11NG to get the token labels, because we have better control of what we do than trying to use SunP11
        final File lib = new File(fileName);
        final String libDir = lib.getParent();
        final String libName = lib.getName();
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir, true);
        final Slot slot = device.getSlot(slotID);
        if (slot != null) {
            return slot.getLabel().toCharArray();
        }
        log.debug(">getTokenLabelLocal: tokenInfo == null");
        return null;
    }
}
