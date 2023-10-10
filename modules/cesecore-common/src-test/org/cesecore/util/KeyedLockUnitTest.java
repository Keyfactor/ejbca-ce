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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Test of {@link KeyedLock}
 */
public class KeyedLockUnitTest {

    @Test
    public void testLockUnlock() {
        final KeyedLock<Integer> lock = new KeyedLock<>();
        assertTrue(lock.tryLock(1));
        lock.release(1);

        assertTrue(lock.tryLock(2));
        lock.release(2);

        assertTrue(lock.tryLock(1));
        lock.release(1);
    }

    @Test
    public void testConflict() {
        final KeyedLock<Integer> lock = new KeyedLock<>();
        assertTrue(lock.tryLock(1));
        assertFalse(lock.tryLock(1));
        lock.release(1);

        // Try again. The lock will contain the key now, but with value == Boolean.FALSE
        assertTrue(lock.tryLock(1));
        assertFalse(lock.tryLock(1));
        lock.release(1);
    }

    @Test
    public void testDoubleRelease() {
        final KeyedLock<Integer> lock = new KeyedLock<>();
        assertTrue(lock.tryLock(1));
        lock.release(1);
        assertThrows(IllegalStateException.class, () -> lock.release(1));
    }
}
