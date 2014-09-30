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

import java.util.Arrays;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.util.UnitParser;

/**
 * Helper class for handling user friendly format of time intervals.
 * 
 * The format is in the form '*y *mo *d *h *m *s *ms' where * is a decimal number and
 * y=years, mo=months, d=days, h=hours, m=minutes, s=seconds, ms=milliseconds. Spaces are optional.
 * 
 * <p>Example to print time in milliseconds as a user friendly string (55m for 55 minutes).</p>
 * <code>
 * CombineTime.getInstance(longtime).toString(CombineTime.TYPE_MINUTES))
 * </code>
 * 
 * <p>Example to parse user friendly time string and get milliseconds (55 minutes = 3300000ms), with default value 1 minute</p>
 * <code>
 * CombineTime.getInstance(stringtime, "1"+CombineTime.TYPE_MINUTES).getLong();
 * </code>
 *  
 * @version $Id$
 */
public class CombineTime {

	public static final long MILLISECONDS_PER_YEAR = 31536000000L; //a year = 365 days
	public static final long MILLISECONDS_PER_MONTH = 2592000000L; //a month= 30 days
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
	   
	private static final Logger log = Logger.getLogger(CombineTime.class);
	private static final UnitParser unitParser = new UnitParser(Arrays.asList(new String[] {TYPE_YEARS, TYPE_MONTHS, TYPE_DAYS, TYPE_HOURS, TYPE_MINUTES, TYPE_SECONDS, TYPE_MILLISECONDS}));
	
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
	private CombineTime(long time) {
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
		milliSeconds = time % MILLISECONDS_PER_SECOND;
	}

	/**
	 * @param time AyBmoCdDhEmFsGu meaning A years, B months, C days, D hours, E minutes, F seconds and G milliseconds
	 * @throws Exception if unable to parse a String
	 */
	private CombineTime(String time) throws Exception {
		parse(time);
	}

	/**
	 * @param time AyBmoCdDhEmFsGu meaning A years, B months, C days, D hours, E minutes, F seconds and G milliseconds
	 * @param defaultTime AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @throws Exception if unable to parse a String
	 */
	private CombineTime(String time, String defaultTime) throws Exception {
		if (time == null || time.trim().length()==0) {
			time = defaultTime;
		}
		parse(time);
	}
		
	/**
	 * Get new instance of class.
	 * @param time milliseconds
	 * @return new instance of class
	 */
	public static CombineTime getInstance(long time) {
		return new CombineTime(time);
	}
		
	/**
	 * Get new instance of class.
	 * @param time AyBmoCdDhEmFsGu meaning A years, B months, C days, D hours, E minutes, F seconds and G milliseconds
	 * @return new instance of class or null if there were errors
	 */
	public static CombineTime getInstance(String time) {
		CombineTime cTime = null;
		try {
			cTime = new CombineTime(time);
		} catch (Exception e) {
			log.info("Failed to parse time \"" + time + "\". " + e.getMessage());
		}
		return cTime;
	}
		
	/**
	 * Get new instance of class.
	 * @param time AyBmoCdDhEmFsGu meaning A years, B months, C days, D hours, E minutes, F seconds and G milliseconds
	 * @param defaultTime AyBmoCdDhEmFsGu meaning A years, B months, C days, D hours, E minutes, F seconds and G milliseconds
	 * @return new instance of class or null if there were errors
	 */
	public static CombineTime getInstance(String time, String defaultTime) {
		CombineTime cTime = null;
		try {
			cTime = new CombineTime(time, defaultTime);
		} catch (Exception e) {
			log.info("Failed to parse time or defaultTime \"" + time + "\", \"" + defaultTime + "\". " + e.getMessage());
		}
		return cTime;
	}

	/**
	 * Parse string and convert it to usable local variables.
	 * @param time AyBmoCdDhEmFsGu meaning A years, B months, C days, D hours, E minutes, F seconds and G milliseconds
	 * @throws Exception if an parsing error occurs
	 */
	private void parse(String time) throws Exception {
		Map<String, Long> values = unitParser.parse(time);
		years = (Long) values.get(TYPE_YEARS);
		months = (Long) values.get(TYPE_MONTHS);
		days = (Long) values.get(TYPE_DAYS);
		hours = (Long) values.get(TYPE_HOURS);
		minutes = (Long) values.get(TYPE_MINUTES);
		seconds = (Long) values.get(TYPE_SECONDS);
		milliSeconds = (Long) values.get(TYPE_MILLISECONDS);
		longTime = years * MILLISECONDS_PER_YEAR + months * MILLISECONDS_PER_MONTH + days * MILLISECONDS_PER_DAY + hours * MILLISECONDS_PER_HOUR + minutes * MILLISECONDS_PER_MINUTE + seconds * MILLISECONDS_PER_SECOND + milliSeconds;
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
		String ret = "";
		if(getYears() != 0) {
			ret += getYears() + TYPE_YEARS;
		}
		if(getMonths() != 0) {
			ret += (ret.length()==0?"":" ") + getMonths() + TYPE_MONTHS;
		}
		if (getDays() != 0) {
			ret += (ret.length()==0?"":" ") + getDays() + TYPE_DAYS;
		}
		if (getHours() != 0) {
			ret += (ret.length()==0?"":" ") + getHours() + TYPE_HOURS;
		}
		if (getMinutes() != 0) {
			ret += (ret.length()==0?"":" ") + getMinutes() + TYPE_MINUTES;
		}
		if (getSeconds() != 0) {
			ret += (ret.length()==0?"":" ") + getSeconds() + TYPE_SECONDS;
		}
		if (getMilliSeconds() != 0) {
			ret += (ret.length()==0?"":" ") + getMilliSeconds() + TYPE_MILLISECONDS;
		}
		if (ret.length()==0) {
			ret = "0" + zeroType;
		}
		return ret;
	}
}	
