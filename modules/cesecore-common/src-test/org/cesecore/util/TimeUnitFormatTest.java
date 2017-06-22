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

package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

/** 
 * Test of the TimeUnitFormat class.
 *  
 * @version $Id$
 */
public class TimeUnitFormatTest {

    // duplicate code from SimpleTime start
    public static final long MILLISECONDS_PER_YEAR = 31536000000L; // 365 days
    public static final long MILLISECONDS_PER_MONTH = 2592000000L; // 30 days
    public static final long MILLISECONDS_PER_DAY = 86400000L;
    public static final long MILLISECONDS_PER_HOUR = 3600000L;
    public static final long MILLISECONDS_PER_MINUTE = 60000L;
    public static final long MILLISECONDS_PER_SECOND = 1000L;

    public static final String TYPE_YEARS = "y";
    public static final String TYPE_MONTHS = "mo";
    public static final String TYPE_DAYS = "d";
    public static final String TYPE_HOURS = "h";
    public static final String TYPE_MINUTES = "m";
    public static final String TYPE_SECONDS = "s";
    public static final String TYPE_MILLISECONDS = "ms";

    private static final Map<String, Long> MILLISECONDS_FACTOR = new LinkedHashMap<String, Long>();
    static {
        MILLISECONDS_FACTOR.put(TYPE_YEARS, MILLISECONDS_PER_YEAR);
        MILLISECONDS_FACTOR.put(TYPE_MONTHS, MILLISECONDS_PER_MONTH);
        MILLISECONDS_FACTOR.put(TYPE_DAYS, MILLISECONDS_PER_DAY);
        MILLISECONDS_FACTOR.put(TYPE_HOURS, MILLISECONDS_PER_HOUR);
        MILLISECONDS_FACTOR.put(TYPE_MINUTES, MILLISECONDS_PER_MINUTE);
        MILLISECONDS_FACTOR.put(TYPE_SECONDS, MILLISECONDS_PER_SECOND);
        MILLISECONDS_FACTOR.put(TYPE_MILLISECONDS, 1L);
    }
    // duplicate code from SimpleTime end

    public TimeUnitFormatTest() {
    }

    /**
     * Tests the default parser and formatter (with '*y *mo *d *h *m *s *ms'). 
     * Both methods of the test object (a.parseMillis() and a.format()) are tested here, to not to double code.
     * Values with '0' are not rendered (i.e. '1y 0mo' -> '1y').
     */
    @Test
    public void testParserAndFormatter() throws Exception {
        final TimeUnitFormat parser = SimpleTime.getMilliSecondsFormat();
        
        // test zero type
        String type = TYPE_DAYS;
        String time = "0y";
        long millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 0, millis);
        assertEquals("'" + time + "' input formatted.", "0" + type, parser.format(millis, MILLISECONDS_FACTOR, type));
        
        // test positive part string
        time = "1y2mo3d4h7ms";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 1 * MILLISECONDS_PER_YEAR + 2 * MILLISECONDS_PER_MONTH + 3 * MILLISECONDS_PER_DAY + 4 * MILLISECONDS_PER_HOUR + 7, millis);
        assertEquals("'" + time + "' input formatted.", "1y 2mo 3d 4h 7ms", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test positive full string 
        time = "1y2mo3d4h5m6s7ms";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 1 * MILLISECONDS_PER_YEAR + 2 * MILLISECONDS_PER_MONTH + 3 * MILLISECONDS_PER_DAY
                + 4 * MILLISECONDS_PER_HOUR + 5 * MILLISECONDS_PER_MINUTE + 6 * MILLISECONDS_PER_SECOND + 7, millis);
        assertEquals("'" + time + "' input formatted.", "1y 2mo 3d 4h 5m 6s 7ms", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));

        // test negative value
        time = "-1y-2mo-3d-4h-5m-6s-7ms";
        millis = parser.parseMillis(time);
        System.out.println("MILLIS: " + millis);
        assertEquals("'" + time + "' input long value.", -1 * MILLISECONDS_PER_YEAR - 2 * MILLISECONDS_PER_MONTH - 3 * MILLISECONDS_PER_DAY
                - 4 * MILLISECONDS_PER_HOUR - 5 * MILLISECONDS_PER_MINUTE - 6 * MILLISECONDS_PER_SECOND - 7, millis);
        assertEquals("'" + time + "' input formatted.", "-1y -2mo -3d -4h -5m -6s -7ms", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test canonical form for positive results no negative values! (i.e.: '400d' -> '1y 1mo 5d' NOT '1y 2mo -25d')
        time = "400d";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 400 * MILLISECONDS_PER_DAY, millis);
        assertEquals("'" + time + "' input formatted.", "1y 1mo 5d", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test negative canonical form -> only negative values! (i.e.: '-400d' -> '-1y -1mo -5d' NOT '-1y -2mo +25d')
        time = "-400d";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", -400 * MILLISECONDS_PER_DAY, millis);
        assertEquals("'" + time + "' input formatted.", "-1y -1mo -5d", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test positive sum with optional sequence
        time = " -1y 3d 3d -6s -14s  2y  7ms -2mo  -4h-5m";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 1 * MILLISECONDS_PER_YEAR + 3 * MILLISECONDS_PER_DAY + 3 * MILLISECONDS_PER_DAY - 6 * MILLISECONDS_PER_SECOND - 14 * MILLISECONDS_PER_SECOND
                + 7 - 2 * MILLISECONDS_PER_MONTH - 4 * MILLISECONDS_PER_HOUR - 5 * MILLISECONDS_PER_MINUTE, millis);
        assertEquals("'" + time + "' input formatted.", "10mo 10d 19h 54m 40s 7ms", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test negative sum with optional sequence
        time = " -1y 3d 3d -6s -14s  1y  7ms -2mo  -4h-5m";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 3 * MILLISECONDS_PER_DAY + 3 * MILLISECONDS_PER_DAY - 6 * MILLISECONDS_PER_SECOND - 14 * MILLISECONDS_PER_SECOND
                + 7 - 2 * MILLISECONDS_PER_MONTH - 4 * MILLISECONDS_PER_HOUR - 5 * MILLISECONDS_PER_MINUTE, millis);
        assertEquals("'" + time + "' input formatted.", "-1mo -24d -4h -5m -19s -993ms", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test different formats
        time = "   1y   -2mo    3d-4h-5m    -6s      7ms  ";
        millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 1 * MILLISECONDS_PER_YEAR - 2 * MILLISECONDS_PER_MONTH + 3 * MILLISECONDS_PER_DAY
                - 4 * MILLISECONDS_PER_HOUR - 5 * MILLISECONDS_PER_MINUTE - 6 * MILLISECONDS_PER_SECOND + 7, millis);
        assertEquals("'" + time + "' input formatted.", "10mo 7d 19h 54m 54s 7ms", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test unit not defined: z
        try {
            parser.parseMillis("5m  3d 7z -6s -4h 5m 10ms");
            fail("NumberFormatException ('Illegal characters.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Illegal characters.".equals(e.getMessage()));
        }

        // test other illegal characters (start|end)
        try {
            parser.parseMillis("iiii5m 3d -6s -4h 5m");
            fail("NumberFormatException ('Illegal characters.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Illegal characters.".equals(e.getMessage()));
        }

        // test other illegal characters (start|end)
        try {
            parser.parseMillis("5m 3d -6s -4h 5miiii");
            fail("NumberFormatException ('Illegal characters.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Illegal characters.".equals(e.getMessage()));
        }

        // test null or empty string (=blank)
        try {
            parser.parseMillis(null);
            fail("NumberFormatException ('Cannot parse a blank string.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Cannot parse a blank string.".equals(e.getMessage()));
        }
        try {
            parser.parseMillis("   ");
            fail("NumberFormatException ('Cannot parse a blank string.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Cannot parse a blank string.".equals(e.getMessage()));
        }
    }
    
    /**
     * Tests the default parser and formatter (with '*y *mo *d *h *m *s *ms'). 
     * Both methods of the test object (a.parseMillis() and a.format()) are tested here, to not to double code.
     * Values with '0' are not rendered (i.e. '1y 0mo' -> '1y').
     */
    @Test
    public void test02ParserAndFormatterForSecondsPrecision() throws Exception {
        final TimeUnitFormat parser = SimpleTime.getSecondsFormat();
        
        // test positive full string
        String time = "1y2mo3d4h5m6s";
        long millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 1 * MILLISECONDS_PER_YEAR + 2 * MILLISECONDS_PER_MONTH + 3 * MILLISECONDS_PER_DAY + 4 * MILLISECONDS_PER_HOUR + 5 * MILLISECONDS_PER_MINUTE + 6 * MILLISECONDS_PER_SECOND, millis);
        assertEquals("'" + time + "' input formatted.", "1y 2mo 3d 4h 5m 6s", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test units not defined: z
        try {
            parser.parseMillis("1y2mo3d4h5m6s7ms");
            fail("NumberFormatException ('Illegal characters.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Illegal characters.".equals(e.getMessage()));
        }
    }
    
    /**
     * Tests the default parser and formatter (with '*y *mo *d *h *m *s *ms'). 
     * Both methods of the test object (a.parseMillis() and a.format()) are tested here, to not to double code.
     * Values with '0' are not rendered (i.e. '1y 0mo' -> '1y').
     */
    @Test
    public void test03ParserAndFormatterForDaysPrecision() throws Exception {
        final TimeUnitFormat parser = SimpleTime.getDaysFormat();
        
        // test positive full string
        String time = "1y2mo3d";
        long millis = parser.parseMillis(time);
        assertEquals("'" + time + "' input long value.", 1 * MILLISECONDS_PER_YEAR + 2 * MILLISECONDS_PER_MONTH + 3 * MILLISECONDS_PER_DAY, millis);
        assertEquals("'" + time + "' input formatted.", "1y 2mo 3d", parser.format(millis, MILLISECONDS_FACTOR, TYPE_DAYS));
        
        // test units not defined: z
        try {
            parser.parseMillis("1y2mo3d4h");
            fail("NumberFormatException ('Illegal characters.') expected!");
        } catch (NumberFormatException e) {
            assertTrue("Expected NumberFormatException: " + e.toString(),
                    e instanceof NumberFormatException && "Illegal characters.".equals(e.getMessage()));
        }
    }
}
