/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.repository.util;

import java.util.concurrent.locks.Lock;
import java.util.function.Supplier;

public class SynchronizationUtil {

    public static void synchronizedRunnable(final Lock lock, final Runnable runnable) {
        try {
            lock.lock();
            runnable.run();
        }
        finally {
            lock.unlock();
        }
    }

    public static <T> T synchronizedSupplier(final Lock lock, final Supplier<T> supplier) {
        try {
            lock.lock();
            return supplier.get();
        }
        finally {
            lock.unlock();
        }
    }

}
