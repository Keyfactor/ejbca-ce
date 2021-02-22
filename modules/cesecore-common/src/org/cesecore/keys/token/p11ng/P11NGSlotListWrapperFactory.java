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

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.PKCS11SlotListWrapper;
import org.cesecore.keys.token.PKCS11SlotListWrapperFactory;

/**
 * This class wraps C_GetSlotList call to P11 to get information about slots/tokens and their labels
 * 
 * A slot list and token labels for each slot is cached so that C_GetSlotList() only has to be called once and
 * so that C_GetTokenInfo() only has to be called once for each slot. This means that is additional/new slots are created on a token
 * EJBCA has to be restarted.
 */
public class P11NGSlotListWrapperFactory implements PKCS11SlotListWrapperFactory {
    private static final Logger log = Logger.getLogger(P11NGSlotListWrapperFactory.class);

    private static final int PRIORITY = 2;
    
    private static volatile Map<String, P11NGSlotListWrapper> instances = new HashMap<>();
    private static final Lock lock = new ReentrantLock();

    /**
     * Get an instance of PKCS11SlotListWrapper.
     * @param file the p11 .so file.
     * @return the instance.
     * @throws IllegalArgumentException
     */
    public PKCS11SlotListWrapper getInstance(final File file) throws IllegalArgumentException {
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
            final P11NGSlotListWrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// if instance exist we don't have to wait for lock just grab it.
            }
        }
        try {
            lock.lock();// wait for lock; some other tread might be creating the instance right now.
            final P11NGSlotListWrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// some other thread had already created the instance
            }
            // no other thread has created the instance and no other will since this thread is locking.
            // CK_C_INITIALIZE_ARGS pInitArgs should include CKF_OS_LOCKING_OK
            // We utilize the SunP11 provider for this, a liytle way around, especially if we are using P11NG, but it works
            //Pkcs11SlotLabel.doC_Initialize(file);
            // TODO: do P11NG C_Initialize
            final P11NGSlotListWrapper newP11 = new P11NGSlotListWrapper(canonicalFileName);
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
