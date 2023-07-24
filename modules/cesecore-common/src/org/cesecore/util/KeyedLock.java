/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.util.HashMap;
import java.util.Map;

/**
 * A multi-key lock for skipping concurrent executions
 */
public class KeyedLock<T> {

    private final Map<T,Boolean> lockedResources = new HashMap<>();

    public synchronized boolean tryLock(final T key) {
        boolean running = false;
        final Boolean b = lockedResources.get(key);
        if (b != null) {
            running = b.booleanValue();
        }
        if (!running) {
            lockedResources.put(key, Boolean.TRUE);
        }
        return !running;
    }

    public synchronized void release(final T key) {
        if (!lockedResources.put(key, Boolean.FALSE)) {
            throw new IllegalStateException("Attempted to release lock that was not locked.");
        }
    }
}
