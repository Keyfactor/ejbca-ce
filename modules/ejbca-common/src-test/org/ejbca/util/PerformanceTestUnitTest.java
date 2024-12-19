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
    public void testNextLong_long_long() {
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
