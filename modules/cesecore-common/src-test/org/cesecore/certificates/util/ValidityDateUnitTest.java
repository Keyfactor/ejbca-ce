/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.util;

import static org.junit.Assert.assertEquals;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.cesecore.util.ValidityDate;
import org.junit.Assert;
import org.junit.Test;


/**
 * 
 */
public class ValidityDateUnitTest {

    private static final Logger LOG = Logger.getLogger(ValidityDateUnitTest.class);
    
    public static final String ISO8601_DATE_FORMAT = "yyyy-MM-dd HH:mm:ssZZ";

    
    /** Since the test will run in different time zones we will test combined operations. */
    @Test
    public void testParseFormat() throws ParseException {
        LOG.trace(">testParseFormat");
        final Date nowWithOutMillis = new Date((new Date().getTime()/1000)*1000);   // We will loose the millis in the conversion
        assertEquals(nowWithOutMillis, ValidityDate.parseAsIso8601(ValidityDate.formatAsISO8601(nowWithOutMillis, ValidityDate.TIMEZONE_SERVER)));
        final Date zero = new Date(0);
        assertEquals(zero, ValidityDate.parseAsIso8601(ValidityDate.formatAsISO8601(zero, ValidityDate.TIMEZONE_SERVER)));
        LOG.trace("<testParseFormat");
    }
    
    @Test
    public void testValidityGranularityParsing() throws ParseException {
        String minutesGranularity = "2019-06-19 20:30";
        String secondsGranularity = "2019-06-19 20:30:12";
        // View end entity page uses these
        ValidityDate.getISO8601FromImpliedUTC(minutesGranularity, TimeZone.getDefault());
        ValidityDate.getISO8601FromImpliedUTC(secondsGranularity, TimeZone.getDefault());
        // View/edit EEP uses...
        ValidityDate.getImpliedUTCFromISO8601(minutesGranularity);
        ValidityDate.getImpliedUTCFromISO8601(secondsGranularity);
        
    }

    /** Tests stripSecondsFromIso8601UtcDate with relative and absolute dates */
    @Test
    public void stripSecondsFromIso8601UtcDate() {
        assertEquals("Relative date should not be touched.", "1:2:3", ValidityDate.stripSecondsFromIso8601UtcDate("1:2:3"));
        assertEquals("Old US locale date should not be touched.", "May 31, 2019, 12:07 PM", ValidityDate.stripSecondsFromIso8601UtcDate("May 31, 2019, 12:07 PM"));
        assertEquals("Date without seconds should not be touched.", "2019-12-31 23:45", ValidityDate.stripSecondsFromIso8601UtcDate("2019-12-31 23:45"));
        assertEquals("Date with seconds should have seconds removed.", "2019-12-31 23:45", ValidityDate.stripSecondsFromIso8601UtcDate("2019-12-31 23:45:56"));
    }
    
    @Test
    public void testgetDateFromRelativeTime() throws Exception {
        
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ssXXX");

        String startDateStr = "2021-10-20 14:30:21+04:30";
        Date startDate = format.parse(startDateStr);
        
        String expectedDateStr1 = "2022-01-29 00:40:20+04:30"; 
        Date expectedDate1 = format.parse(expectedDateStr1);
        
        String expectedDateStr2 = "2022-01-29 00:40:21+04:30"; 
        Date expectedDate2 = format.parse(expectedDateStr2);
                
        Assert.assertEquals("", expectedDate1, 
                ValidityDate.getDateFromRelativeTime("100:10:10", startDate, true));
        Assert.assertEquals("", expectedDate2, 
                ValidityDate.getDateFromRelativeTime("100:10:10", startDate, false));
        
        Assert.assertNull("Invalid relative time format accepted.", 
                ValidityDate.getDateFromRelativeTime("100:10:-10", startDate, true));
        Assert.assertNull("Max. 23 hours can be specifed.", 
                ValidityDate.getDateFromRelativeTime("100:26:10", startDate, true));
        Assert.assertNull("Max. 59 minutes can be specifed.", 
                ValidityDate.getDateFromRelativeTime("100:10:61", startDate, true));
        Assert.assertNull("Invalid relative time format accepted.", 
                ValidityDate.getDateFromRelativeTime("100:10", startDate, true));
        
    }
}
