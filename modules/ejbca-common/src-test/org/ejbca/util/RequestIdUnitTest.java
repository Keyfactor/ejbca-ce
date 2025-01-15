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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class RequestIdUnitTest {

    private static final String ORIGINAL_THREAD_NAME = "test-thread-"+ RequestIdUnitTest.class.getSimpleName();

    @Before
    public void setUp() throws Exception {
        RequestId.closeAll();
        Thread.currentThread().setName(ORIGINAL_THREAD_NAME);

        assertNull(RequestId.getCurrent());
        assertFalse(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
        assertEquals(ORIGINAL_THREAD_NAME, RequestId.getOriginalName());
    }

    @After
    public void tearDown() throws Exception {
        assertNull(RequestId.getCurrent());
        assertFalse(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
        assertEquals(ORIGINAL_THREAD_NAME, RequestId.getOriginalName());

        RequestId.closeAll();
    }

    @Test
    public void testDoFilter_oneFilter() {
        // When
        try (RequestId requestId = RequestId.getCurrentOrCreate()) {
            // Then
            assertNotNull(requestId);
            assertSame(requestId, RequestId.getCurrent());
            assertEquals(1, requestId.getCounter());
            assertTrue(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
        }
    }

    @Test
    public void testDoFilter_twoFilters() {
        // Outer filter

        // When
        try (final RequestId outerRequestId = RequestId.getCurrentOrCreate()) {
            // Then
            assertNotNull(outerRequestId);
            assertSame(outerRequestId, RequestId.getCurrent());
            assertEquals(1, outerRequestId.getCounter());
            assertTrue(Thread.currentThread().getName().contains(RequestId.SEPARATOR));

            // Inner filter

            // When
            try (final RequestId innerRequestId = RequestId.getCurrentOrCreate()) {
                // Then
                assertNotNull(innerRequestId);
                assertSame(innerRequestId, RequestId.getCurrent());
                assertSame(outerRequestId, RequestId.getCurrent());
                assertEquals(2, outerRequestId.getCounter());
                assertTrue(Thread.currentThread().getName().contains(RequestId.SEPARATOR));
                assertEquals(outerRequestId.getId(), innerRequestId.getId());
            }
        }
    }

}
