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

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * Helper class for handling user friendly format of time intervals with years, 
 * months and days.
 * 
 * The format is in the form '*y *mo *d' where * is a decimal number and
 * y=years, mo=months, d=days. Spaces are optional.
 *  
 * @version $Id$
 */
public class YearMonthDayTime {

	public static final String TYPE_YEARS = "y";
	public static final String TYPE_MONTHS = "mo";
	public static final String TYPE_DAYS = "d";
	
	private static final UnitParser unitParser = new UnitParser(Arrays.asList(new String[] {TYPE_YEARS, TYPE_MONTHS, TYPE_DAYS}));	    
    private static final Logger log = Logger.getLogger(YearMonthDayTime.class);
    private Map<String, Long> values;

	/**
	 * @param time AyBmoCd meaning A years, B months, C days
	 * @throws NumberFormatException if an parsing error occurs
	 * @throws IllegalArgumentException if time is empty (or only contains white-spaces)
	 * @throws NullPointerException if time is null
	 */
	private YearMonthDayTime(String time) throws NumberFormatException {
		values = unitParser.parse(time);
	}
	
	/**
	 * @param time AyBmoCd meaning A years, B months, C days
	 * @param defaultTime AyBmoCd meaning A years, B months, C days
	 * @throws NumberFormatException if an parsing error occurs
	 * @throws IllegalArgumentException if time is empty (or only contains white-spaces)
	 * @throws NullPointerException if time is null
	 */
	private YearMonthDayTime(String time, String defaultTime) throws NumberFormatException {
		if (time == null || time.trim().length()==0) {
			time = defaultTime;
		}
		values = unitParser.parse(time);
	}
	
	/**
	 * Get new instance of class.
	 * @param time AyBmoCd meaning A years, B months, C days
	 * @return new instance of class or null if there were errors
	 */
	public static YearMonthDayTime getInstance(String time) {
		YearMonthDayTime simpleTime = null;
		try {
			simpleTime = new YearMonthDayTime(time);
		} catch (Exception e) {
			log.info("Failed to parse time \"" + time + "\". " + e.getMessage());
		}
		return simpleTime;
	}
	
	/**
	 * Get new instance of class.
	 * @param time AyBmoCd meaning A years, B months, C days
	 * @param defaultTime AyBmoCd meaning A years, B months, C days
	 * @return new instance of class or null if there were errors
	 */
	public static YearMonthDayTime getInstance(String time, String defaultTime) {
		YearMonthDayTime simpleTime = null;
		try {
			simpleTime = new YearMonthDayTime(time, defaultTime);
		} catch (Exception e) {
			log.info("Failed to parse time or defaultTime \"" + time + "\", \"" + defaultTime + "\". " + e.getMessage());
		}
		return simpleTime;
	}

	/** @return The years field */
	public long getYears() { return values.get(TYPE_YEARS); }
	
	/** @return The months field */
	public long getMonths() { return values.get(TYPE_MONTHS); }
	
	/** @return The days field */
	public long getDays() { return values.get(TYPE_DAYS); }
	
	/**
	 * Calculates the number of days from <i>date</i> until the years, months and days this object represents has elapsed.
	 * @param date Date to count days to
	 * @return Number of days from date until the years, months and days this object represents has elapsed
	 * */
	public long daysFrom(Date date) {
		final long result;
		
		// Get a calendar for the date we want to compare with
		// We are only counting whole days so set the time to 12:00 (noon)
     	Calendar cal = Calendar.getInstance();
     	cal.setTime(date);
     	cal.set(Calendar.HOUR_OF_DAY, 12);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        final long fromTime = cal.getTimeInMillis();
        
        // Step forward a number of years, months and days
    	cal.add(Calendar.YEAR, (int) getYears());
    	cal.add(Calendar.MONTH, (int) getMonths());
    	cal.add(Calendar.DATE, (int) getDays());
    	
    	// Calculate the time difference in days between the two times
    	final double diff = ((double)(cal.getTimeInMillis() - fromTime)) / (double)(1000*60*60*24);
    	
    	// Due to day light savings time it might not be an integer number
    	result = (long) Math.round(diff); 
    	
       	return result;
	}
	
	/**
	 * Get nicely formatted form of this object using days as default type.
	 * @return time in the format AyBmoCd meaning A years, B months, C days or "0d" if time is 0.
	 */
	public String toString() {
		return toString(TYPE_DAYS);
	}
	
	/**
	 * @param zeroType the type of the returned value if '0'. One of the YearMonthDayTime.TYPE_ constants.
	 * @return time in the format AyBmoCd meaning A years, B months, C days
	 */
	public String toString(String zeroType) {
		return unitParser.toString(values, zeroType);
	}
}
