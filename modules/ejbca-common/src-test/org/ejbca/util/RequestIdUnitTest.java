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

package org.ejbca.util;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class RequestIdUnitTest {

    private static final String ORIGINAL_THREAD_NAME = "test-thread-"+ RequestIdUnitTest.class.getSimpleName();

    private void closeAllRequestIds() {
        Set<Thread> threadSet = Thread.getAllStackTraces().keySet();
        for (Thread thread : threadSet) {
            thread.setName(thread.getName().split(RequestId.SEPARATOR)[0]);
        }
    }

    @Before
    public void setUp() throws Exception {
        closeAllRequestIds();
        Thread.currentThread().setName(ORIGINAL_THREAD_NAME);
        assertNull(RequestId.parse());
        assertFalse(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
        assertEquals(1, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
    }

    @After
    public void tearDown() throws Exception {
        closeAllRequestIds();
        assertNull(RequestId.parse());
        assertFalse(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
        assertEquals(1, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
    }

    @Test
    public void testDoFilter_oneFilter() {
        // When
        try (RequestId requestId = new RequestId()) {
            // Then
            assertNotNull(requestId);
            assertEquals(requestId, RequestId.parse());
            assertTrue(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
            assertEquals(2, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
        }
        assertEquals(1, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
    }

    @Test
    public void testDoFilter_twoFilters() {
        // Outer filter

        // When
        try (final RequestId outerRequestId = new RequestId()) {
            // Then
            assertNotNull(outerRequestId);
            assertEquals(outerRequestId, RequestId.parse());
            assertTrue(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
            assertEquals(2, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);

            // Inner filter

            // When
            try (final RequestId innerRequestId = new RequestId()) {
                // Then
                assertNotNull(innerRequestId);
                assertEquals(outerRequestId, RequestId.parse());
                assertEquals(innerRequestId.getId(), outerRequestId.getId());
                assertTrue(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
                assertEquals(2, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
            }
            assertEquals(2, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
        }
        assertEquals(1, Thread.currentThread().getName().split(RequestId.SEPARATOR).length);
    }

}
