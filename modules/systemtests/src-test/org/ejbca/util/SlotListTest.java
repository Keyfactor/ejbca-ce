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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;


/**
 * Tests SlotList
 * 
 * @version $Id$
 */
public class SlotListTest {

    private static final class TestInfo {
        public final String s;
        public final List<String> contains = new ArrayList<String>();
        public final List<String> doesntContain = new ArrayList<String>();
        public boolean skipToString = false;
        
        public TestInfo(String s) {
            this.s = s;
        }
        
        public TestInfo contains(String... list) {
            contains.addAll(Arrays.asList(list));
            return this;
        }
        
        public TestInfo doesntContain(String... list) {
            doesntContain.addAll(Arrays.asList(list));
            return this;
        }
        
        public TestInfo skipToString() {
            skipToString = true;
            return this;
        }
    }
    
    private static final TestInfo[] tests = {
        // Test simple usage
        new TestInfo("").doesntContain("0", "1", "2", "3"),
        new TestInfo("1").contains("1").doesntContain("0", "2", "3", "i0", "i1"),
        new TestInfo("1,2").skipToString().contains("1", "2").doesntContain("0", "3", "i0", "i1"),
        new TestInfo("1-3").contains("1", "2", "3").doesntContain("0", "4", "5", "i0", "i1"),
        new TestInfo("i1-i3").contains("i1", "i2", "i3").doesntContain("0", "1", "2", "3", "i0", "i4"),
        
        // Test multiple ranges
        new TestInfo("1-3, 6").contains("1", "3", "6").doesntContain("0", "4", "5", "7"),
        new TestInfo("1-3, 6-7").contains("1", "3", "6", "7").doesntContain("0", "4", "5", "8"),
        
        // Test overlaps
        new TestInfo("1-3, 4").skipToString().contains("1", "3", "4").doesntContain("0", "5"),
        new TestInfo("1-3, 4-5").skipToString().contains("1", "3", "4", "5").doesntContain("0", "6"),
        new TestInfo("1-3, 2-4").skipToString().contains("1", "2", "3", "4").doesntContain("0", "5"),
        new TestInfo("2-4, 1-3").skipToString().contains("1", "2", "3", "4").doesntContain("0", "5"),
        new TestInfo("3-4, 1,2").skipToString().contains("1", "2", "3", "4").doesntContain("0", "5"),
        
        // Test long ranges
        new TestInfo("1-32000").contains("1", "32000").doesntContain("0", "32001"),
        new TestInfo("0-32000").contains("0", "32000").doesntContain("32001"),
        
        // Test infinite ranges
        new TestInfo("1-").contains("1", String.valueOf(Integer.MAX_VALUE)).doesntContain("0"),
        new TestInfo("-10").contains("0").doesntContain("11"),
        new TestInfo("-").contains("0", String.valueOf(Integer.MAX_VALUE)).doesntContain("i1"),
        new TestInfo("i1-i").contains("i1", "i"+Integer.MAX_VALUE).doesntContain("i0", "1"),
        new TestInfo("i-i").contains("i0", "i"+Integer.MAX_VALUE).doesntContain("1"),
    };
    

    @Test
    public void testParseSlotList() {
        assertNull("SlotList.fromString(null) should return null", SlotList.fromString(null));
        for (TestInfo test : tests) {
            SlotList.fromString(test.s);
        }
    }
    
    @Test
    public void testSlotListContains() {
        for (TestInfo test : tests) {
            SlotList sl = SlotList.fromString(test.s);
            for (String yes : test.contains) {
                assertTrue("list "+test.s+" should contain "+yes, sl.contains(yes));
            }
        }
    }
    
    @Test
    public void testSlotListDoesntContain() {
        for (TestInfo test : tests) {
            SlotList sl = SlotList.fromString(test.s);
            for (String no : test.doesntContain) {
                assertFalse("list "+test.s+" shouldn't contain "+no, sl.contains(no));
            }
        }
    }
    
    final String[] badSyntaxes = {
        "x", "x1", "i", "i,", "9-1", "--", "1--2"
    };
    
    @Test
    public void testBadSyntax() {
        for (String bad : badSyntaxes) {
            try {
                SlotList.fromString(bad);
                fail("parseSlotList(\""+bad+"\") should have thrown IllegalArgumentException");
            } catch (IllegalArgumentException e) { /* expected */ }
        }
    }
    
    @Test
    public void testToString() {
        for (TestInfo test : tests) {
            if (test.skipToString) continue;
            SlotList sl = SlotList.fromString(test.s);
            assertEquals(test.s, sl.toString());
        }
    }

}
