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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

/**
 * Helper class for handling user friendly format of time intervals.
 * 
 * The format is in the form '*d *h *m *s *ms' where * is a decimal number and
 * d=days, h=hours, m=minutes, s=seconds, ms=milliseconds. Spaces are optional.
 *  
 * @version $Id: $
 */
public class SimpleTime {
	
    public static final String patternString = "^(\\d+[dD])?(\\d+[hH])?(\\d+[mM])?(\\d+[sS])?(\\d+[mM][sS])?$";

    public static final long MILLISECONDS_PER_DAY = 86400000L;
	public static final long MILLISECONDS_PER_HOUR = 3600000L;
	public static final long MILLISECONDS_PER_MINUTE = 60000L;
	public static final long MILLISECONDS_PER_SECOND = 1000L;
	
	public static final String TYPE_DAYS = "d";
	public static final String TYPE_HOURS = "h";
	public static final String TYPE_MINUTES = "m";
	public static final String TYPE_SECONDS = "s";
	public static final String TYPE_MILLISECONDS = "ms";
    
    private static final Logger log = Logger.getLogger(SimpleTime.class);
	private static final Pattern pattern = Pattern.compile(patternString);
	private static final Pattern valuePattern = Pattern.compile("(\\d+)");
	private static final Pattern typePattern = Pattern.compile("(\\D+)");
	
    private long longTime = 0;
    private long days = 0;
    private long hours = 0;
    private long minutes = 0;
    private long seconds = 0;
    private long milliSeconds = 0;

	/**
	 * @param time milliseconds
	 */
	private SimpleTime(long time) {
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
	 * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @throws Exception if unable to parse a String
	 */
	private SimpleTime(String time) throws Exception {
		parse(time);
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
		parse(time);
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
	 * Parse string and convert it to usable local variables.
	 * @param time AdBhCmDsEu meaning A days, B hours, C minutes, D seconds and E milliseconds
	 * @throws Exception if an parsing error occurs
	 */
	private void parse(String time) throws Exception {
		if (time == null) {
			throw new Exception("Time is null.");
		}
		time = time.replaceAll("\\s", "");	// Remove all white-spaces
		if (time.length()==0) {
			throw new Exception("Time is empty.");
		}
		Matcher matcher = pattern.matcher(time);
		if (!matcher.find()) {
			throw new Exception("Not a match.");
		}
		for (int i=0; i<matcher.groupCount(); i++) {
			String match = matcher.group(i+1);
			if (match != null) {
				Matcher valueMatcher = valuePattern.matcher(match);
				Matcher typeMatcher = typePattern.matcher(match);
				if (!valueMatcher.find() || !typeMatcher.find()) {
					throw new Exception("Not a match.");
				}
				long value = Long.parseLong(valueMatcher.group(1));
				String type = typeMatcher.group(1).toLowerCase();
				if (TYPE_DAYS.equals(type)) {
					days = value;
				} else if (TYPE_HOURS.equals(type)) {
					hours = value;
				} else if (TYPE_MINUTES.equals(type)) {
					minutes = value;
				} else if (TYPE_SECONDS.equals(type)) {
					seconds = value;
				} else if (TYPE_MILLISECONDS.equals(type)) {
					milliSeconds = value;
				}
			}
		}
		longTime = days * MILLISECONDS_PER_DAY + hours * MILLISECONDS_PER_HOUR + minutes * MILLISECONDS_PER_MINUTE + seconds * MILLISECONDS_PER_SECOND + milliSeconds;
	}

	/** Get the total number of milliseconds for this time (including days, hours etc).*/
	public long getLong() { return longTime; }
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
		if (getDays() != 0) {
			ret += getDays() + TYPE_DAYS;
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
