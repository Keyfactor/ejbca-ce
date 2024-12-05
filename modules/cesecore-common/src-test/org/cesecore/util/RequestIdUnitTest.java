package org.cesecore.util;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class RequestIdUnitTest {

    private static final String ORIGINAL_THREAD_NAME = "test-thread-"+ RequestIdUnitTest.class.getSimpleName();

    @Before
    public void setUp() throws Exception {
        Thread.currentThread().setName(ORIGINAL_THREAD_NAME);
    }

    @Test
    public void testDoFilter_oneFilter() {
        // Given

        // When
        RequestId requestId = new RequestId();

        // Then
        assertEquals(2, RequestId.split().length);

        // When
        requestId.clear();

        // Then
        assertEquals(1, RequestId.split().length);
    }

    @Test
    public void testDoFilter_twoFilters() {
        // Outer filter
        assertEquals(1, RequestId.split().length);
        RequestId outerRequestId = new RequestId();
        assertEquals(2, RequestId.split().length);
        String outerRequestIdString = RequestId.split()[1];

        // Inner filter
        RequestId innerRequestId = new RequestId();
        String innerRequestIdString = RequestId.split()[1];
        assertEquals(outerRequestIdString, innerRequestIdString);
        innerRequestId.clear();
        assertEquals(2, RequestId.split().length);

        // Outer filter
        outerRequestId.clear();
        assertEquals(1, RequestId.split().length);
    }


}
