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
 * @version $Id$
 */
public class ValidityDateUnitTest {

    private static final Logger LOG = Logger.getLogger(ValidityDateUnitTest.class);
    private static final String RELATIVE = "relative";
    private static final String ABSOLUTE = "absolute";
    
    public static final String ISO8601_DATE_FORMAT = "yyyy-MM-dd HH:mm:ssZZ";
    private static final long LONG_VALUE = ((long) Integer.MAX_VALUE)+1;

    
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
    @Deprecated
    public void testEncodeRelativeBeforePostUpdateOfVersion661() {
        LOG.trace(">testEncodeRelativeBeforePostUpdateOfVersion661");
        final long ERROR_CODE = -1;
        encodeBeforePostUpdateOfVersion661(RELATIVE, "0", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "0d", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "-1d", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "1d", 1);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "1d1h1m", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "0y0m1d", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "0y0mo1d", 1);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "1d0y0mo", 1);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "+0y-0mo+1d", 1);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "ii +0y-0mo+1d", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "+0y-ii0mo+1d", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(RELATIVE, "+0y-0mo+1d ii", ERROR_CODE);
        LOG.trace("<testEncodeRelativeBeforePostUpdateOfVersion661");
    }
    
    @Test
    @Deprecated
    public void testEncodeAbsoluteBeforePostUpdateOfVersion661() {
        LOG.trace(">testEncodeAbsoluteBeforePostUpdateOfVersion661");
        final long ERROR_CODE = -1;
        encodeBeforePostUpdateOfVersion661(ABSOLUTE, "yyyy-MM-dd HH:mm:ssZZ", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(ABSOLUTE, "2011-05-09T16:58:00+00:00", ERROR_CODE);
        encodeBeforePostUpdateOfVersion661(ABSOLUTE, "2011-05-09 16:58:00+00:00", 1304960280000L);
        LOG.trace("<testEncodeAbsoluteBeforePostUpdateOfVersion661");
    }
    
    @Deprecated
    private void encodeBeforePostUpdateOfVersion661(final String type, final String subject, final long result) {
        assertEquals("Test of " + type + " date " + subject + " failed.", result, ValidityDate.encodeBeforeVersion661(subject));
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
    
    @Test
    @Deprecated
    public void testGetStringBeforeVersion661() throws ParseException {
        LOG.trace(">testGetStringBeforeVersion661");
        // Test relative times (<Integer.MAX_VALUE)
        getStringInternalRelBeforeVersion661(0, "0d");
        getStringInternalRelBeforeVersion661(1, "1d");
        // Test absolute time (==Integer.MAX_VALUE)
        getStringInternalAbsBeforeVersion661(Integer.MAX_VALUE, "1970-01-25 20:31:23+00:00");
        // Test absolute times (>Integer.MAX_VALUE)
        getStringInternalAbsBeforeVersion661(LONG_VALUE, "1970-01-25 20:31:23+00:00");
        getStringInternalAbsBeforeVersion661(1304960280000L, "2011-05-09 16:58:00+00:00");
        LOG.trace("<testGetStringBeforeVersion661");
    }

    @Deprecated
    private void getStringInternalRelBeforeVersion661(final long subject, final String result) {
        assertEquals("Failed to fetch relative time for " + subject, result, ValidityDate.getStringBeforeVersion661(subject));
    }

    @Deprecated
    private void getStringInternalAbsBeforeVersion661(final long subject, final String result) throws ParseException {
        assertEquals("Failed to fetch absolute time for " + subject, ValidityDate.parseAsIso8601(result), ValidityDate.parseAsIso8601(ValidityDate.getStringBeforeVersion661(subject)));
    }
    
    @Test
    @Deprecated
    public void testGetDateBeforeVersion661() {
        LOG.trace(">testGetDateBeforeVersion661");
        final Date now = new Date();
        // Test errors (no error handling available in this method)
        //testGetDateInternal(0, null, null);
        //testGetDateInternal(-1, now, null);
        // Test relative times (<Integer.MAX_VALUE)
        getDateInternalBeforeVersion661(0, now, new Date(now.getTime() - 1000));
        getDateInternalBeforeVersion661(1, now, new Date(now.getTime() + 24*3600*1000 - 1000));
        // Test absolute time (==Integer.MAX_VALUE)
        getDateInternalBeforeVersion661(Integer.MAX_VALUE, now, new Date(Integer.MAX_VALUE));
        // Test absolute times (>Integer.MAX_VALUE)
        getDateInternalBeforeVersion661(LONG_VALUE, now, new Date(LONG_VALUE));
        LOG.trace("<testGetDateBeforeVersion661");
    }

    @Deprecated
    private void getDateInternalBeforeVersion661(final long subjectLEncoded, final Date subjectFromDate, final Date result) {
        assertEquals("Failed to fetch date for " + subjectLEncoded + " and " + subjectFromDate, result, ValidityDate.getDateBeforeVersion661(subjectLEncoded, subjectFromDate));
    }

    @Test
    @Deprecated
    public void testGetEncodeBeforeVersion661() {
        LOG.trace(">testGetEncodeBeforeVersion661");
        // Test relative times (<Integer.MAX_VALUE)
        assertEquals("", -1L, ValidityDate.encodeBeforeVersion661(ValidityDate.getStringBeforeVersion661(0)));
        assertEquals("", 1L, ValidityDate.encodeBeforeVersion661(ValidityDate.getStringBeforeVersion661(1)));
        // Test absolute times (>Integer.MAX_VALUE)
        final long nowWithOutSeconds = (new Date().getTime()/60000)*60000;
        assertEquals("", nowWithOutSeconds, ValidityDate.encodeBeforeVersion661(ValidityDate.getStringBeforeVersion661(nowWithOutSeconds)));
        LOG.trace("<testGetEncodeBeforeVersion661");
    }

    @Test
    @Deprecated
    public void testEncodeGetBeforeVersion661() throws ParseException {
        LOG.trace(">testEncodeGetBeforeVersion661");
        assertEquals("", ValidityDate.parseAsIso8601("2011-05-09 16:58:00+00:00"), ValidityDate.parseAsIso8601(ValidityDate.getStringBeforeVersion661(ValidityDate.encodeBeforeVersion661("2011-05-09 16:58:00+00:00"))));
        assertEquals("", ValidityDate.parseAsIso8601("1970-01-25 20:32:00+00:00"), ValidityDate.parseAsIso8601(ValidityDate.getStringBeforeVersion661(ValidityDate.encodeBeforeVersion661("1970-01-25 20:32:00+00:00"))));
        assertEquals("", ValidityDate.parseAsIso8601("2011-05-09 16:58:12"), ValidityDate.parseAsIso8601(ValidityDate.getStringBeforeVersion661(ValidityDate.encodeBeforeVersion661("2011-05-09 16:58:12"))));
        assertEquals("", ValidityDate.parseAsIso8601("2011-05-09 16:58"), ValidityDate.parseAsIso8601(ValidityDate.getStringBeforeVersion661(ValidityDate.encodeBeforeVersion661("2011-05-09 16:58"))));
        assertEquals("", ValidityDate.parseAsIso8601("2012-02-29"), ValidityDate.parseAsIso8601(ValidityDate.getStringBeforeVersion661(ValidityDate.encodeBeforeVersion661("2012-02-29"))));
        assertEquals("", ValidityDate.parseAsIso8601("2012-02-29").getTime(), ValidityDate.encodeBeforeVersion661("2012-02-29 00:00:00+00:00"));
        LOG.trace("<testEncodeGetBeforeVersion661");
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
