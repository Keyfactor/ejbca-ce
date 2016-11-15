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
 
package org.cesecore.util;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * Helper class for handling user friendly format of time intervals.
 * 
 * The format is in the form '*d *h *m *s *ms' where * is a decimal number and
 * d=days, h=hours, m=minutes, s=seconds, ms=milliseconds. Spaces are optional.
 *  
 * @version $Id$
 */
public class SimpleTime {

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
	
    public static final String PRECISION_MILLISECONDS = "milliseconds";
    public static final String PRECISION_SECONDS = "seconds";
    public static final String PRECISION_DAYS = "days";
    
    public static final List<String> AVAILABLE_PRECISIONS = Arrays.asList( new String[] { 
            PRECISION_MILLISECONDS, PRECISION_SECONDS, PRECISION_DAYS });
	    
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
	
    private static final Logger log = Logger.getLogger(SimpleTime.class);
	
    private static final TimeUnitFormat DAYS_FORMAT_INSTANCE = new TimeUnitFormat(
            Arrays.asList(new String[] { TYPE_YEARS, TYPE_MONTHS, TYPE_DAYS }), MILLISECONDS_FACTOR);

    private static final TimeUnitFormat SECONDS_FORMAT_INSTANCE = new TimeUnitFormat(
            Arrays.asList(new String[] { TYPE_YEARS, TYPE_MONTHS, TYPE_DAYS, TYPE_HOURS, TYPE_MINUTES, TYPE_SECONDS }), MILLISECONDS_FACTOR);

    // Limitation 'ms' (or 'mo') MUST NOT be configured after units containing one of their characters 'm', 's' or 'o'!
    private static final TimeUnitFormat MILLISECONDS_FORMAT_INSTANCE = new TimeUnitFormat(
            Arrays.asList(new String[] { TYPE_MILLISECONDS, TYPE_YEARS, TYPE_MONTHS, TYPE_DAYS, TYPE_HOURS, TYPE_MINUTES, TYPE_SECONDS}), MILLISECONDS_FACTOR);
    
    private long longTime = 0;
    private long years = 0;
    private long months = 0;
    private long days = 0;
    private long hours = 0;
    private long minutes = 0;
    private long seconds = 0;
    private long milliSeconds = 0;

	/**
	 * @param time milliseconds
	 */
	private SimpleTime(long time) {
	    setTime(time);
	}

	/**
	 * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @throws Exception if unable to parse a String
	 */
	private SimpleTime(String time) throws Exception {
	    setTime(parseMillies(time));
	}

	/**
	 * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @param defaultTime AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @throws Exception if unable to parse a String
	 */
	private SimpleTime(String time, String defaultTime) throws Exception {
		if (time == null || time.trim().length()==0) {
			time = defaultTime;
		}
		setTime(parseMillies(time));
	}
	
	/**
	 * Get new instance of class.
	 * @param time milliseconds
	 * @return new instance of class
	 */
	public static SimpleTime getInstance(long time) {
		return new SimpleTime(time);
	}
	
	/**
	 * Get new instance of class.
	 * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @return new instance of class or null if there were errors
	 */
	public static SimpleTime getInstance(String time) {
		SimpleTime simpleTime = null;
		try {
			simpleTime = new SimpleTime(time);
		} catch (Exception e) {
			log.info("Failed to parse time \"" + time + "\". " + e.getMessage());
		}
		return simpleTime;
	}
	
	/**
	 * Get new instance of class.
	 * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @param defaultTime AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @return new instance of class or null if there were errors
	 */
	public static SimpleTime getInstance(String time, String defaultTime) {
		SimpleTime simpleTime = null;
		try {
			simpleTime = new SimpleTime(time, defaultTime);
		} catch (Exception e) {
			log.info("Failed to parse time or defaultTime \"" + time + "\", \"" + defaultTime + "\". " + e.getMessage());
		}
		return simpleTime;
	}
	
	/**
     * Gets the time unit formatter with the default formatting style for days
     * (with year(y), months (mo) and days (d)).
     * 
     * @return a time unit formatter.
     */
    public static final TimeUnitFormat getDaysFormat() {
        return DAYS_FORMAT_INSTANCE;
    }

    /**
     * Gets the time unit formatter with the default formatting style for
     * seconds (with year(y), months (mo), days (d), hours (h), minutes (m) and
     * seconds (s)).
     * 
     * @return a time unit formatter.
     */
    public static final TimeUnitFormat getSecondsFormat() {
        return SECONDS_FORMAT_INSTANCE;
    }

    /**
     * Gets the time unit formatter with the default formatting style for
     * milliseconds (with year(y), months (mo), days (d), hours (h), minutes (m), 
     * seconds (s) and milliseconds (ms)).
     * 
     * @return a time unit formatter.
     */
    public static final TimeUnitFormat getMilliSecondsFormat() {
        return MILLISECONDS_FORMAT_INSTANCE;
    }
    
    /**
     * Gets the TimeUnitFormat by precision.
     * @param precision
     * @return the TimeUnitFormat with the desired precision if existent.
     * @see SimpleTime#AVAILABLE_PRECISIONS
     */
    public static final TimeUnitFormat getTimeUnitFormatOrThrow(final String precision) throws IllegalArgumentException {
        TimeUnitFormat result = null;
        if (!AVAILABLE_PRECISIONS.contains(precision)) {
            throw new IllegalArgumentException("Could not get TimeUnitForm for precision: " + precision);
        }
        switch (precision) {
            case SimpleTime.PRECISION_MILLISECONDS: 
                result = SimpleTime.getMilliSecondsFormat();
                break;
            case SimpleTime.PRECISION_SECONDS: 
                result = SimpleTime.getSecondsFormat();
                break;
            case SimpleTime.PRECISION_DAYS: 
                result = SimpleTime.getDaysFormat();
                break;
            default:
                result = SimpleTime.getSecondsFormat();
        }
        return result;
    }
    
    public static final String toString(final long millis, final String zeroType) {
        return SimpleTime.getMilliSecondsFormat().format(millis, MILLISECONDS_FACTOR, zeroType);
    }
    
    public static final long parseMillies(String time) throws NumberFormatException {
        return SimpleTime.getMilliSecondsFormat().parseMillis(time);
    }
	
	private void setTime(long time) {
	    longTime = time;
        years = time / MILLISECONDS_PER_YEAR;
        time %= MILLISECONDS_PER_YEAR;
        months = time / MILLISECONDS_PER_MONTH;
        time %= MILLISECONDS_PER_MONTH;
        days = time / MILLISECONDS_PER_DAY;
        time %= MILLISECONDS_PER_DAY;
        hours = time / MILLISECONDS_PER_HOUR;
        time %= MILLISECONDS_PER_HOUR;
        minutes = time / MILLISECONDS_PER_MINUTE;
        time %= MILLISECONDS_PER_MINUTE;
        seconds = time / MILLISECONDS_PER_SECOND;
        time %= MILLISECONDS_PER_SECOND;
        milliSeconds = time;
	}

	/** Get the total number of milliseconds for this time (including days, hours etc).*/
	public long getLong() { return longTime; }
	public long getYears() { return years; }
	public long getMonths() { return months; }
	public long getDays() { return days; }
	public long getHours() { return hours; }
	public long getMinutes() { return minutes; }
	public long getSeconds() { return seconds; }
	public long getMilliSeconds() { return milliSeconds; }

	/**
     * Get nicely formatted form of this object using seconds as default type.
     * @return time in the format AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds or "0s" if time is 0.
     */
    public String toString() {
        return toString(TYPE_SECONDS);
    }
    
    /**
     * @param zeroType the type of the returned value if '0'. One of the SimpleType.TYPE_ constants.
     * @return time in the format AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
     */
    public String toString(String zeroType) {
        return SimpleTime.getMilliSecondsFormat().format(getLong(), MILLISECONDS_FACTOR, zeroType); 
    }
}
