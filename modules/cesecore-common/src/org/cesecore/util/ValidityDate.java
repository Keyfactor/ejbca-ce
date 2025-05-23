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

import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;

/**
 * Class for encoding and decoding certificate validity and end date.
 * 
 */
public class ValidityDate {
	/** The date and time format defined in ISO8601. The 'T' can be omitted (and we do to save some parsing cycles). */
	public static final String ISO8601_DATE_FORMAT = "yyyy-MM-dd HH:mm:ssZZ";
	public static final TimeZone TIMEZONE_UTC = TimeZone.getTimeZone("UTC");
	public static final TimeZone TIMEZONE_SERVER = TimeZone.getDefault();
	// Offset for period of time from notBefore through notAfter, inclusive. See ECA-9523, ECA-10327.
	public static final long NOT_AFTER_INCLUSIVE_OFFSET = 1000;

	private static final Logger log = Logger.getLogger(ValidityDate.class);
	// Time format for storage where implied timezone is UTC
	private static final String[] IMPLIED_UTC_PATTERN = {"yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss"};
	private static final String[] IMPLIED_UTC_PATTERN_TZ = {"yyyy-MM-dd HH:mmZZ", "yyyy-MM-dd HH:mm:ssZZ"};
	// Time format for human interactions
	private static final String[] ISO8601_PATTERNS = {
	   // These must have timezone on date-only format also, since it has a time also (which is 00:00).
	   // If the timezone is omitted then the string "+00:00" is appended to the date before parsing
	   ISO8601_DATE_FORMAT, "yyyy-MM-dd HH:mmZZ", "yyyy-MM-ddZZ"
    };
	
	/** Pattern used to separate seconds (in $2 reference) and everything else (in $1)*/
	private static final Pattern SECONDS_MATCHER = Pattern.compile("(\\d{4,4}-\\d\\d-\\d\\d \\d\\d:\\d\\d)(:\\d\\d)");

	private static final String RELATIVE_TIME_REGEX = "\\d+:\\d?\\d:\\d?\\d"; // example: 90:0:0 or 0:15:30
    private static final String ISO_TIME_REGEX = "\\d{4,}-(0\\d|10|11|12)-[0123]\\d( \\d\\d:\\d\\d(:\\d\\d)?)?([+-]\\d\\d:\\d\\d)?"; // example: 2019-12-31 or 2019-12-31 23:59:59+00:00
    public static final String VALIDITY_TIME_REGEX = "^(" + RELATIVE_TIME_REGEX + "|" + ISO_TIME_REGEX + ")$";
    private static final Pattern VALIDITY_TIME_PATTERN = Pattern.compile(VALIDITY_TIME_REGEX);
	
    // Can't be instantiated
    private ValidityDate() {
    }
	
	/** Parse a String in the format "yyyy-MM-dd HH:mm" as a date with implied TimeZone UTC. */
	public static Date parseAsUTC(final String dateString) throws ParseException {
		return DateUtils.parseDateStrictly(dateString+"+00:00", IMPLIED_UTC_PATTERN_TZ);
	}

	/** Parse a String in the format "yyyy-MM-dd HH:mm:ssZZ". The hour/minutes, seconds and timezone are optional parts. */
	public static Date parseAsIso8601(final String dateString) throws ParseException {
	    try {
		    return DateUtils.parseDateStrictly(dateString, ISO8601_PATTERNS);
	    } catch (ParseException e) {
	        // Try again with timezone. In DateUtils, the default timezone seems to be the server
	        // timezone and not UTC, so we can't have date formats without "ZZ".
	        return DateUtils.parseDateStrictly(dateString+"+00:00", ISO8601_PATTERNS);
	    }
	}
	
	/**
	 * 
	 * @param dateString a string describing a date
	 * @return true if dateString is in the format "yyyy-MM-dd HH:mm:ssZZ"
	 */
	public static boolean isValidIso8601Date(final String dateString) {
	    try {
	        if(StringUtils.isEmpty(dateString)) { 
	            return false;
	        } else {
	            parseAsIso8601(dateString);
	        }
	        return true;
	    } catch(ParseException e) {
	        return false;
	    }
	}

	/** Convert a Date to the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC. */
	public static String formatAsUTC(final Date date) {
		return FastDateFormat.getInstance(IMPLIED_UTC_PATTERN[0], TIMEZONE_UTC).format(date);
	}

	/** Convert a Date to the format "yyyy-MM-dd HH:mm:ss" with implied TimeZone UTC. */
	public static String formatAsUTCSecondsGranularity(final Date date) {
	    return FastDateFormat.getInstance(IMPLIED_UTC_PATTERN[1], TIMEZONE_UTC).format(date);
	}
	
	/** Convert a absolute number of milliseconds to the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC. */
	public static String formatAsUTC(final long millis) {
		return FastDateFormat.getInstance(IMPLIED_UTC_PATTERN[0], TIMEZONE_UTC).format(millis);
	}
	
	/** Convert a absolute number of milliseconds to the format "yyyy-MM-dd HH:mm:ss" with implied TimeZone UTC. */
    public static String formatAsUTCSecondsGranularity(final long millis) {
        return FastDateFormat.getInstance(IMPLIED_UTC_PATTERN[1], TIMEZONE_UTC).format(millis);
    }
	
	/** Convert a Date to the format "yyyy-MM-dd HH:mm:ssZZ" (the T is not required). The server's time zone is used. */
	public static String formatAsISO8601(final Date date, final TimeZone timeZone) {
		return FastDateFormat.getInstance(ISO8601_PATTERNS[0], timeZone).format(date);
	}

	/** Convert a Date in milliseconds to the format "yyyy-MM-dd HH:mm:ssZZ". The server's time zone is used. */
	public static String formatAsISO8601ServerTZ(final long millis, final TimeZone timeZone) {
		return FastDateFormat.getInstance(ISO8601_PATTERNS[0], TIMEZONE_SERVER).format(millis);
	}
	
	/** Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC. */
	public static String getImpliedUTCFromISO8601(final String dateString) throws ParseException {
		return formatAsUTCSecondsGranularity(parseAsIso8601(dateString));
	}
	
	/** Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to "yyyy-MM-dd HH:mm:ssZZ". */
	public static String getISO8601FromImpliedUTC(final String dateString, final TimeZone timeZone) throws ParseException {
		return formatAsISO8601(parseAsUTC(dateString), timeZone);
	}
	
	/**
	 * Encoding of the validity for a CA or certificate profile. Either delta time or end date.
	 * @param validity *y *mo *d or absolute date in the form "yyyy-MM-dd HH:mm:ssZZ"
	 * @return delta time in days if h*m*d*; milliseconds since epoch if valid absolute date; -1 if neither
	 * @throws IllegalArgumentException if the argument is null
	 */
	@Deprecated
	public static long encodeBeforeVersion661(final String validity) {
		long result = -1;
        try {
            // parse ISO8601 time stamp, i.e 'yyyy-MM-dd HH:mm:ssZZ'.
            result = parseAsIso8601(validity).getTime();
        } catch (ParseException e) {
            try {
                // parse SimpleTime string with format '*y *mo *d ...'.
                final long days = SimpleTime.getDaysFormat().parseMillis(validity) / (1000 * 60 * 60 *24);
                if (days > 0) {
                    if (isDeltaTimeBeforeVersion661(days)) {
                        result = days;
                    } else {
                        result = Integer.MAX_VALUE-1;
                        log.info(validity + " is relative time format, but too far in the future. Limiting to " + result + " days.");
                    }
                }
            } catch(NumberFormatException nfe) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot decode '" + validity + "' as ISO8601 date or relative time format ('3y 6mo 10d').");
                }
            }
        }
		return result;
	}

	/**
	 * Decodes encoded value to string in the form "yyyy-MM-dd HH:mm:ssZZ" or "1234d" (relative days).
	 * @param lEncoded If this is below Integer.MAX_VALUE it is interpreted as a number of days to firstDate, otherwise an unix timestamp.
	 */
	@Deprecated
	public static String getStringBeforeVersion661(final long lEncoded) {
		if (isDeltaTimeBeforeVersion661(lEncoded)) {
			return SimpleTime.toString(lEncoded * 24 * 60 * 60 * 1000, SimpleTime.TYPE_DAYS);
		}
		return formatAsISO8601ServerTZ(lEncoded, TIMEZONE_SERVER);		
	}
	
	/**
	 * Decodes encoded value to Date.
	 * @param lEncoded encoded value. If this is below Integer.MAX_VALUE it is interpreted as a number of days to firstDate, otherwise an unix timestamp.
	 * @param firstDate date to be used if encoded value is a delta time. Can never be null.
	 */
	@Deprecated
	public static Date getDateBeforeVersion661(final long lEncoded, final Date firstDate) {
		if (isDeltaTimeBeforeVersion661(lEncoded) ) {
			return new Date(firstDate.getTime() + (lEncoded * 24 * 60 * 60 * 1000) - 1000);
		}
		return new Date(lEncoded);
	}
    
	/**
     * Decodes encoded value to Date.
     * <p>
     * For relative dates, one second is subtracted to comply with RFC 5280 section 4.1.2.5,
     * which states that the end date should be interpreted as inclusive (i.e. a certificate with
     * exactly 1 year between the notBefore and notAfter would have 1 second too long validity).
     * <p>
     * Note that different certificate types have different semantics for the expiration time:
     * <ul>
     * <li>X.509: expiration time is inclusive
     * <li>CVC: expiration does not have a time part, only date, so seconds are not relevant
     * <li>SSH: expiration time is exclusive
     * </ul>
     *
     * @param encodedValidity a relative time string (SimpleTime) or a date in ISO8601 format.
     * @param firstDate date to be used if encoded validity is a relative time.
     * @param notAfterIsInclusive whether the date is inclusive. Set to true for X.509/CVC and false for SSH.
     * @return the end date or null if a date or relative time could not be read.
     * @see org.cesecore.util.SimpleTime
     * @see org.cesecore.util.ValidityDate
     * @see org.cesecore.certificates.ca.CAInfo#isExpirationInclusive()
     */
	public static Date getDate(final String encodedValidity, final Date firstDate, final boolean notAfterIsInclusive) {
	    try {
	        // We think this is the most common, so try this first, it's fail-fast
	        final long millis = SimpleTime.parseMillis(encodedValidity);
	        final long endSecond = notAfterIsInclusive ? NOT_AFTER_INCLUSIVE_OFFSET: 0;
	        final Date endDate = new Date(firstDate.getTime() + millis - endSecond);
	        return endDate;
	    } catch(NumberFormatException nfe) {
	        if (log.isDebugEnabled()) {
	            log.debug("Could not read encoded validity as relative date: " +encodedValidity+", "+ nfe.getMessage());
	        }
	        try {
	            return parseAsIso8601(encodedValidity);
	        } catch(ParseException p) {
	            log.error("Could not read encoded validity: " +encodedValidity+", "+ p.getMessage());
	            return null;
	        }
	    }
	}

	/** If below the integer capacity we have stored a relative date in days, otherwise it is an absolute time in milliseconds. */
	@Deprecated
	public static boolean isDeltaTimeBeforeVersion661(final long lEncoded) {
		return lEncoded < Integer.MAX_VALUE;	// This could probably be <= instead??
	}
		
	/**
	 * Rolls the given date one day forward or backward, until a date with a day not included in the restrictions (list of weekdays) is reached.
	 * @param date the date to change.
	 * @param restrictionsForWeekdays an array, { Calendar.SUNDAY, Calendar.MONDAY, etc}
	 * @param before roll back (or forward if false)
	 * @return the new date instance applied to the restrictions
	 * @throws IllegalArgumentException if given date or weekday restriction are null or all weekdays shall be excluded!
	 */
	public static Date applyExpirationRestrictionForWeekdays(final Date date, boolean[] restrictionsForWeekdays, boolean before) throws IllegalArgumentException {
	    if (null == date) {
	        throw new IllegalArgumentException("Date cannot be null!");
	    }
	    if (null == restrictionsForWeekdays) {
	        throw new IllegalArgumentException("Weekday restrictions cannot be null!");
	    }
	    boolean allDaysExcluded = true;
	    for (boolean enabled: restrictionsForWeekdays) {
	        if (!enabled) {
	            allDaysExcluded = false;
	        }
	    }
	    if (allDaysExcluded) {
	        throw new IllegalArgumentException("Weekday restrictions cannot be applied if all weekdays are excluded!");
	    }
        final Calendar calendar = Calendar.getInstance(); 
        calendar.setTime( date);
        final int endDay = calendar.get(Calendar.DAY_OF_WEEK);
        if (log.isDebugEnabled()) {
            log.debug(">applyExpirationRestrictionForWeekdays for end date " + ValidityDate.formatAsISO8601ServerTZ( date.getTime(), ValidityDate.TIMEZONE_SERVER) + " with day " + endDay + " restrictions " + Arrays.toString(restrictionsForWeekdays));
        }
        if (restrictionsForWeekdays[endDay-1]) {
            final int translation = before ? -1 : 1;
            while(restrictionsForWeekdays[calendar.get(Calendar.DAY_OF_WEEK)-1]) {
                calendar.add(Calendar.DAY_OF_MONTH, translation); 
            }
            if (log.isDebugEnabled()) {
                log.debug("Expiration restrictions for weekdays applied: Date changed from " + formatAsISO8601(date, TIMEZONE_SERVER) + " to " + formatAsISO8601(calendar.getTime(), TIMEZONE_SERVER));
            }
            return calendar.getTime();
        }
        return date;
	}

	/** Strips the seconds part of a date string on the form yyyy-MM-dd hh:mm */
	public static String stripSecondsFromIso8601UtcDate(final String dateString) {
	    return SECONDS_MATCHER.matcher(dateString).replaceFirst("$1");
	}
	
	/** Returns true if the date is on the form yyyy-MM-dd hh:mm:ss (or abbreviated) or in relative format, d:h:m */
	public static boolean isAbsoluteTimeOrDaysHoursMinutes(final String dateString) {
	    return VALIDITY_TIME_PATTERN.matcher(dateString).matches();
	}

	/**
	 * Check if the validity date is a relative date string of days:hours:minutes format
	 * @param dateString	a date string
	 */
	public static boolean isRelativeTime(final String dateString) {
		return dateString.matches(RELATIVE_TIME_REGEX);
	}

	/**
	 * Check if the relative date in day:hours:minutes format is valid. Mainly checking
	 * hours and minutes columns.
	 * @param dateString	a date string in relative format
	 * @return
	 */
	public static boolean isValidRelativeTime(final String dateString) {
		final String[] endTimeArray = dateString.split(":");

		return Long.parseLong(endTimeArray[1]) <= 23 && Long.parseLong(endTimeArray[2]) <= 59;
	}

	/**
	 * Parse date from relative time format of days:hours:minutes. Follows same convention as getDate(String, Date, boolean).
	 * 
	 * @param encodedValidity a relative time string(days:hours:minutes).
     * @param firstDate date to be used if encoded validity is a relative time.
     * @param notAfterIsInclusive whether the date is inclusive. Set to true for X.509/CVC and false for SSH.
     * @return the end date or null if a date or relative time could not be read.
	 * 
	 * @see org.cesecore.util.ValidityDate#getDate(String, Date, boolean)
	 */
	public static Date getDateFromRelativeTime(final String encodedValidity, final Date firstDate, final boolean notAfterIsInclusive) {
	    if(!encodedValidity.matches(RELATIVE_TIME_REGEX)) {
	        log.error("Invalid format for relative time, expected days:hours:minutes(9999:23:59).");
	        return null;
	    }
	    
	    final String[] endTimeArray = encodedValidity.split(":");
        if (Long.parseLong(endTimeArray[1]) > 23 || Long.parseLong(endTimeArray[2]) > 59) {
            log.error("Invalid hours or minutes in relative time.");
            return null;
        }
        final long relative = (Long.parseLong(endTimeArray[0]) * 24 * 60 + Long.parseLong(endTimeArray[1]) * 60 +
                Long.parseLong(endTimeArray[2])) * 60 * 1000;
        long endSecond = notAfterIsInclusive ? NOT_AFTER_INCLUSIVE_OFFSET: 0;
        // If we haven't set a startTime, use "now"
        final Date startDate = (firstDate == null) ? new Date(): firstDate;
        final Date endTimeDate = new Date(startDate.getTime() + relative - endSecond);
	    log.debug("Parsed and concluded end date: " + endTimeDate);
	    return endTimeDate;
	}
}
