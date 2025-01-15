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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class PerformanceTestUnitTest {

    private PerformanceTest performanceTest;

    @Before
    public void setUp() throws Exception {
        performanceTest = new PerformanceTest();
    }

    @Test
    public void testNextLongBoundary() {
        long min = 3;
        long max = 10;
        for (int i = 0; i < 100; i++) {
            long next = performanceTest.nextLong(min, max);
            String msg = "next=" + next + ", min=" + min + ", max=" + max+", ";
            assertTrue(msg+"next is expected to be >= min", next >= min);
            assertTrue(msg+"next is expected to be < max", next < max);
        }
    }

}
