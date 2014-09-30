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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Calendar;

import org.junit.Test;


/** 
 * Test of the YearMonthDayTime helper class.
 *  
 * @version $Id$
 */
public class YearMonthDayTimeTest {
    
    /**
     * Test parsing without default value.
     */
    @Test
    public void test01ParseWithoutDefault() throws Exception {
        // Test empty and bad input without default
        failHelper("", null);
        failHelper("0", null);
        failHelper("d", null);
        failHelper("1d0", null);
        failHelper("10s-10ms", null);
        // Test parsing full format
        yearMonthDayTimeHelper("0y0mo0d", null, false, 0, 0, 0);
        yearMonthDayTimeHelper("1y1mo1d", null, false, 1, 1, 1);
        yearMonthDayTimeHelper("1y2mo3d", null, false, 1, 2, 3);
        yearMonthDayTimeHelper("10y10mo10d", null, false, 10, 10, 10);
        // Test parsing one value at the time
        yearMonthDayTimeHelper("10y", null, false, 10, 0, 0);
        yearMonthDayTimeHelper("10mo", null, false, 0, 10, 0);
        yearMonthDayTimeHelper("10d", null, false, 0, 0, 10);
        // Test parsing of capital letters
        yearMonthDayTimeHelper("1Y2MO3D", null, false, 1, 2, 3);
        yearMonthDayTimeHelper("5mO", null, false, 0, 5, 0);
        yearMonthDayTimeHelper("5Mo", null, false, 0, 5, 0);
        // Test with spaces
        yearMonthDayTimeHelper(" 1y2mo3d ", null, false, 1, 2, 3);
        yearMonthDayTimeHelper("1y 2mo 3d", null, false, 1, 2, 3);
    }
    
    /**
     * Test parsing with default value.
     */
    @Test
    public void test02ParseWithDefault() throws Exception {
        // Test empty and bad input with bad default
        failHelper("", "");
        failHelper("", "0");
        failHelper("0", "");
        // Test empty input with ok default
        // Test parsing full format
        yearMonthDayTimeHelper("", "0y0mo0d", false, 0, 0, 0);
        yearMonthDayTimeHelper(null, "1y1mo1d", false, 1, 1, 1);
        yearMonthDayTimeHelper("", "1y2mo3d", false, 1, 2, 3);
        yearMonthDayTimeHelper(null, "10y10mo10d", false, 10, 10, 10);
        // Test parsing one value at the time
        yearMonthDayTimeHelper("", "10y", false, 10, 0, 0);
        yearMonthDayTimeHelper(null, "10mo", false, 0, 10, 0);
        yearMonthDayTimeHelper("", "10d", false, 0, 0, 10);
        // Test parsing of capital letters
        yearMonthDayTimeHelper("", "1Y2MO3D", false, 1, 2, 3);
        yearMonthDayTimeHelper("", "5mO", false, 0, 5, 0);
        yearMonthDayTimeHelper("", "5Mo", false, 0, 5, 0);
        // Test with spaces
        yearMonthDayTimeHelper("", " 1y2mo3d ", false, 1, 2, 3);
        yearMonthDayTimeHelper("", "1y 2mo 3d", false, 1, 2, 3);
    }
    
    /**
     * Test formatting.
     */
    @Test
    public void test03Format() throws Exception {
        assertEquals("10y", YearMonthDayTime.getInstance("10y").toString());
        assertEquals("10mo", YearMonthDayTime.getInstance("10mo").toString());
        assertEquals("10d", YearMonthDayTime.getInstance("10d").toString());
        assertEquals("0d", YearMonthDayTime.getInstance("0y").toString());
        assertEquals("1y3d", YearMonthDayTime.getInstance("1y3d").toString().replaceAll("\\s", ""));
        assertEquals("1y2mo3d", YearMonthDayTime.getInstance("1y2mo3d").toString().replaceAll("\\s", ""));
    }
    
    /**
     * Test calculation of days from a given date.
     */
    @Test
    public void test04DaysFrom() throws Exception {
        YearMonthDayTime oneYear = YearMonthDayTime.getInstance("1y");
        YearMonthDayTime oneMonth = YearMonthDayTime.getInstance("1mo");
        YearMonthDayTime oneDay = YearMonthDayTime.getInstance("1d");
        YearMonthDayTime twentyDays = YearMonthDayTime.getInstance("20d");
        
        Calendar today = Calendar.getInstance();
        today.set(2009, 7, 19, 0, 0, 0);
        
        assertEquals("one year", 365, oneYear.daysFrom(today.getTime()));
        assertEquals("one month", 31, oneMonth.daysFrom(today.getTime()));
        assertEquals("one day", 1, oneDay.daysFrom(today.getTime()));
        
        // Day light savings time: winter +20 days and there is summer time
        today.set(2011, 2, 7, 9, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 2, 7, 0, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 2, 7, 23, 59, 59);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 2, 7, 2, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 2, 7, 3, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 2, 7, 4, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 9, 11, 0, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 9, 11, 23, 59, 59);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 9, 11, 2, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 9, 11, 3, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 9, 11, 4, 0, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
        
        today.set(2011, 6, 10, 23, 59, 0);
        assertEquals("20 days", 20, twentyDays.daysFrom(today.getTime()));
    }
    
    /**
     * Helper for tests that we expect to fail.
     */
    private void failHelper(String time, String defaultTime) {
        yearMonthDayTimeHelper(time, defaultTime, true, 0, 0, 0);
    }
    
    /**
     * Get a new YearMonthDayTime object and verify that it was created correctly.
     */
    private void yearMonthDayTimeHelper(String time, String defaultTime, boolean fail, long years, long months, long days) {
        YearMonthDayTime ymodTime;
        if (defaultTime == null) {
            ymodTime = YearMonthDayTime.getInstance(time);
        } else {
            ymodTime = YearMonthDayTime.getInstance(time, defaultTime);
        }
        if (fail) {
            assertNull("'"+time+"' input.", ymodTime);
            return;
        } else {
            assertNotNull("'"+time+"' input.", ymodTime);
        }
        assertEquals("'"+time+"' input.", years, ymodTime.getYears());
        assertEquals("'"+time+"' input.", months, ymodTime.getMonths());
        assertEquals("'"+time+"' input.", days, ymodTime.getDays());
        
        if(ymodTime.getYears() != 0 || ymodTime.getMonths() != 0 || ymodTime.getDays() != 0) {
            if (defaultTime != null) {
                assertEquals("'"+defaultTime+"' input.", defaultTime.toLowerCase().replaceAll("\\s", ""), ymodTime.toString().replaceAll("\\s", ""));
            } else {
                assertEquals("'"+time+"' input.", time.toLowerCase().replaceAll("\\s", ""), ymodTime.toString().replaceAll("\\s", ""));
            }
        }
    }
}
