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
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.PKCS11SlotListWrapperFactory;

/**
 *
 * This class wraps sun.security.pkcs11.wrapper.PKCS11, so that we can access the native C_GetSlotList PKCS11 
 * call directly to get information about slots/tokens and their labels.
 * 
 * A slot list and token labels for each slot is cached so that C_GetSlotList() only has to be called once and
 * so that C_GetTokenInfo() only has to be called once for each slot. This means that is additional/new slots are created on a token
 * EJBCA has to be restarted.
 * 
 * The {@link #getInstance(File)} method must be called before any SunPKCS#11 provider is created.
 */
public class SunP11SlotListWrapperFactory implements PKCS11SlotListWrapperFactory {
    private static final Logger log = Logger.getLogger(SunP11SlotListWrapperFactory.class);

    private static final int PRIORITY = 1;
    
    private static volatile Map<String, SunP11SlotListWrapper> instances = new HashMap<>();
    private static final Lock lock = new ReentrantLock();
    /**
     * Get an instance of SunP11SlotListWrapper.
     * @param file the p11 .so file.
     * @return the instance.
     * @throws IllegalArgumentException
     */
    public SunP11SlotListWrapper getInstance(final File file) throws IllegalArgumentException {
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
            final SunP11SlotListWrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// if instance exist we don't have to wait for lock just grab it.
            }
        }
        try {
            lock.lock();// wait for lock; some other tread might be creating the instance right now.
            final SunP11SlotListWrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// some other thread had already created the instance
            }
            // no other thread has created the instance and no other will since this thread is locking.
            // CK_C_INITIALIZE_ARGS pInitArgs should include CKF_OS_LOCKING_OK
            // We utilize the SunP11 provider for this, a little way around, especially if we are using P11NG, but it works
            Pkcs11SlotLabel.doC_Initialize(file);
            final SunP11SlotListWrapper newP11 = new SunP11SlotListWrapper(canonicalFileName);
            instances.put(canonicalFileName, newP11);
            return newP11;
        } finally {
            lock.unlock();// now other threads might get the instance.
        }
    }

    @Override
    public int getPriority() {
        return PRIORITY;
    }
    
}
