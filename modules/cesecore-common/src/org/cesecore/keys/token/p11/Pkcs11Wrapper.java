/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice.Slot;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;

/**
 *
 * This class wraps some calls to P11 to get information about slots/tokens and their labels
 * 
 * A slot list and token labels for each slot is cached so that C_GetSlotList() only has to be called once and
 * so that C_GetTokenInfo() only has to be called once for each slot. This means that is additional/new slots are created on a token
 * EJBCA has to be restarted.
 * 
 * This class is used through the UI both when using SunP11 and P11NG, to display slot labels.
 *
 * The {@link #getInstance(File)} method must be called before any SunPKCS#11 provider is created.
 */
public class Pkcs11Wrapper {
    private static final Logger log = Logger.getLogger(Pkcs11Wrapper.class);

    private static volatile Map<String, Pkcs11Wrapper> instances = new HashMap<>();
    private static final Lock lock = new ReentrantLock();
    private final HashMap<Long, char[]> labelMap;
    private final long slotList[];
    private final String fileName;

    private Pkcs11Wrapper(final String fileName) {
        this.fileName = fileName;
        labelMap = new HashMap<>();
        slotList = C_GetSlotList();
        for (long id : slotList) {
            labelMap.put(id, getTokenLabelLocal(id));
        }
    }

    /**
     * Get an instance of the class.
     * @param file the p11 .so file.
     * @return the instance.
     * @throws IllegalArgumentException
     */
    public static Pkcs11Wrapper getInstance(final File file) throws IllegalArgumentException {
        if (log.isTraceEnabled()) {
            log.trace(">getInstance: " + file.getAbsolutePath());
        }
        final String canonicalFileName;
        try {
            canonicalFileName = file.getCanonicalPath();
        } catch (IOException e) {
            throw new IllegalArgumentException(file+" is not a valid filename.",e );
        }
        {
            final Pkcs11Wrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// if instance exist we don't have to wait for lock just grab it.
            }
        }
        try {
            lock.lock();// wait for lock; some other tread might be creating the instance right now.
            final Pkcs11Wrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// some other thread had already created the instance
            }
            // no other thread has created the instance and no other will since this thread is locking.
            // CK_C_INITIALIZE_ARGS pInitArgs should include CKF_OS_LOCKING_OK
            // We utilize the SunP11 provider for this, a liytle way around, especially if we are using P11NG, but it works
            Pkcs11SlotLabel.doC_Initialize(file);
            final Pkcs11Wrapper newP11 = new Pkcs11Wrapper(canonicalFileName);
            instances.put(canonicalFileName, newP11);
            return newP11;
        } finally {
            lock.unlock();// now other threads might get the instance.
        }
    }

    /**
     * Get a (cached) list of p11 slot IDs to slots that has a token.
     * @return (cached) list of slot IDs.
     */
    public long[] getSlotList() {
        return slotList;
    }

    /**
     * Get the token label of a specific slot ID.
     * @param slotID the ID of the slot
     * @return the token label, or null if no matching token was found.
     */
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
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
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
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final Slot slot = device.getSlot(slotID);
        if (slot != null) {
            return slot.getLabel().toCharArray();
        }
        log.debug(">getTokenLabelLocal: tokenInfo == null");
        return null;
    }
}
