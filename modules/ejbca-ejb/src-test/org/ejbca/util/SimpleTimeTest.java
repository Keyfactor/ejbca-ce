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

package org.ejbca.util;

import junit.framework.TestCase;

/** 
 * Test of the SimpleTime helper class.
 *  
 * @version $Id$
 */
public class SimpleTimeTest extends TestCase {
    
    public SimpleTimeTest(String name) { super(name); }

    protected void setUp() throws Exception { }
    protected void tearDown() throws Exception { }

    /**
     * Test parsing without default value.
     */
	public void test01ParseWithoutDefault() throws Exception {
	    // Test empty and bad input without default
		testFailHelper("", null);
		testFailHelper("0", null);
		testFailHelper("d", null);
		testFailHelper("1d0", null);
		testFailHelper("10s-10ms", null);
	    // Test parsing full format
		testHelper("0d0h0m0s0ms", null, false, 0, 0, 0, 0, 0, 0);
		testHelper("1d1h1m1s1ms", null, false, 90061001, 1, 1, 1, 1, 1);
		testHelper("1d2h3m4s5ms", null, false, 93784005, 1, 2, 3, 4, 5);
		testHelper("10d10h10m10s10ms", null, false, 900610010, 10, 10, 10, 10, 10);
	    // Test parsing one value at the time
		testHelper("10d", null, false, 864000000, 10, 0, 0, 0, 0);
		testHelper("10h", null, false, 36000000, 0, 10, 0, 0, 0);
		testHelper("10m", null, false, 600000, 0, 0, 10, 0, 0);
		testHelper("10s", null, false, 10000, 0, 0, 0, 10, 0);
		testHelper("10ms", null, false, 10, 0, 0, 0, 0, 10);
		// Test parsing of capital letters
		testHelper("1D2H3M4S5MS", null, false, 93784005, 1, 2, 3, 4, 5);
		testHelper("5mS", null, false, 5, 0, 0, 0, 0, 5);
		testHelper("5Ms", null, false, 5, 0, 0, 0, 0, 5);
		// Test with spaces
		testHelper(" 1d2h3m4s5ms ", null, false, 93784005, 1, 2, 3, 4, 5);
		testHelper("1d 2h 3m 4s 5ms", null, false, 93784005, 1, 2, 3, 4, 5);
	}
	
    /**
     * Test parsing with default value.
     */
	public void test02ParseWithDefault() throws Exception {
	    // Test empty and bad input with bad default
		testFailHelper("", "");
		testFailHelper("", "0");
		testFailHelper("0", "");
	    // Test empty input with ok default
	    // Test parsing full format
		testHelper("", "0d0h0m0s0ms", false, 0, 0, 0, 0, 0, 0);
		testHelper(null, "1d1h1m1s1ms", false, 90061001, 1, 1, 1, 1, 1);
		testHelper("", "1d2h3m4s5ms", false, 93784005, 1, 2, 3, 4, 5);
		testHelper(null, "10d10h10m10s10ms", false, 900610010, 10, 10, 10, 10, 10);
	    // Test parsing one value at the time
		testHelper("", "10d", false, 864000000, 10, 0, 0, 0, 0);
		testHelper(null, "10h", false, 36000000, 0, 10, 0, 0, 0);
		testHelper("", "10m", false, 600000, 0, 0, 10, 0, 0);
		testHelper(null, "10s", false, 10000, 0, 0, 0, 10, 0);
		testHelper("", "10ms", false, 10, 0, 0, 0, 0, 10);
		// Test parsing of capital letters
		testHelper("", "1D2H3M4S5MS", false, 93784005, 1, 2, 3, 4, 5);
		testHelper("", "5mS", false, 5, 0, 0, 0, 0, 5);
		testHelper("", "5Ms", false, 5, 0, 0, 0, 0, 5);
		// Test with spaces
		testHelper("", " 1d2h3m4s5ms ", false, 93784005, 1, 2, 3, 4, 5);
		testHelper("", "1d 2h 3m 4s 5ms", false, 93784005, 1, 2, 3, 4, 5);
	}
	
    /**
     * Test formatting.
     */
	public void test03Format() throws Exception {
		assertEquals("0s", SimpleTime.getInstance(0L).toString());
		assertEquals("10ms", SimpleTime.getInstance(10L).toString());
		assertEquals("10s", SimpleTime.getInstance(10000L).toString());
		assertEquals("10m", SimpleTime.getInstance(600000L).toString());
		assertEquals("10h", SimpleTime.getInstance(36000000L).toString());
		assertEquals("10d", SimpleTime.getInstance(864000000L).toString());
		assertEquals("1d2h3m4s5ms", SimpleTime.getInstance(93784005L).toString().replaceAll("\\s", ""));
	}
	
	/**
	 * Tests the constructor that takes an argument of type long
	 */
	public void test04ConstructorLong() throws Exception {
		assertEquals(4711, SimpleTime.getInstance(4711).getLong());
	}
	
	/**
	 * Helper for tests that we expect to fail.
	 */
	private void testFailHelper(String time, String defaultTime) {
		testHelper(time, defaultTime, true, 0, 0, 0, 0, 0, 0);
	}
	
	/**
	 * Get a new SimpleTime object and verify that it was created correctly.
	 */
	private void testHelper(String time, String defaultTime, boolean fail, long longTime, long days, long hours, long minutes, long seconds, long milliSeconds) {
		SimpleTime simpleTime;
		if (defaultTime == null) {
			simpleTime = SimpleTime.getInstance(time);
		} else {
			simpleTime = SimpleTime.getInstance(time, defaultTime);
		}
		if (fail) {
			assertNull("'"+time+"' input.", simpleTime);
			return;
		} else {
			assertNotNull("'"+time+"' input.", simpleTime);
		}
		assertEquals("'"+time+"' input.", longTime, simpleTime.getLong());
		assertEquals("'"+time+"' input.", days, simpleTime.getDays());
		assertEquals("'"+time+"' input.", hours, simpleTime.getHours());
		assertEquals("'"+time+"' input.", minutes, simpleTime.getMinutes());
		assertEquals("'"+time+"' input.", seconds, simpleTime.getSeconds());
		assertEquals("'"+time+"' input.", milliSeconds, simpleTime.getMilliSeconds());
		if (simpleTime.getLong() == 0) {
			assertEquals("'"+time+"' input.", "0s", simpleTime.toString());
		} else {
			if (defaultTime != null) {
				assertEquals("'"+defaultTime+"' input.", defaultTime.toLowerCase().replaceAll("\\s", ""), simpleTime.toString().replaceAll("\\s", ""));
			} else {
				assertEquals("'"+time+"' input.", time.toLowerCase().replaceAll("\\s", ""), simpleTime.toString().replaceAll("\\s", ""));
			}
		}
	}
}
