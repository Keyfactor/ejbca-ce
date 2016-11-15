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

import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;

/**
 * Class for encoding and decoding certificate validity and end date.
 * 
 * @version $Id$
 */
public class ValidityDate {
	/** The date and time format defined in ISO8601. The 'T' can be omitted (and we do to save some parsing cycles). */
	public static final String ISO8601_DATE_FORMAT = "yyyy-MM-dd HH:mm:ssZZ";
	public static final TimeZone TIMEZONE_UTC = TimeZone.getTimeZone("UTC");
	public static final TimeZone TIMEZONE_SERVER = TimeZone.getDefault();

	private static final Logger log = Logger.getLogger(ValidityDate.class);
	// Time format for storage where implied timezone is UTC
	private static final String[] IMPLIED_UTC_PATTERN = {"yyyy-MM-dd HH:mm"};
	private static final String[] IMPLIED_UTC_PATTERN_TZ = {"yyyy-MM-dd HH:mmZZ"};
	// Time format for human interactions
	private static final String[] ISO8601_PATTERNS = {
	   // These must have timezone on date-only format also, since it has a time also (which is 00:00).
	   // If the timezone is omitted then the string "+00:00" is appended to the date before parsing
	   ISO8601_DATE_FORMAT, "yyyy-MM-dd HH:mmZZ", "yyyy-MM-ddZZ"
    };
    
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

	/** Convert a Date to the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC. */
	public static String formatAsUTC(final Date date) {
		return FastDateFormat.getInstance(IMPLIED_UTC_PATTERN[0], TIMEZONE_UTC).format(date);
	}
	
	/** Convert a absolute number of milliseconds to the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC. */
	public static String formatAsUTC(final long millis) {
		return FastDateFormat.getInstance(IMPLIED_UTC_PATTERN[0], TIMEZONE_UTC).format(millis);
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
		return formatAsUTC(parseAsIso8601(dateString));
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
                        result = Long.valueOf(Integer.MAX_VALUE-1);
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
			return new Date(firstDate.getTime() + (lEncoded * 24 * 60 * 60 * 1000));
		}
		return new Date(lEncoded);
	}
    
	/**
     * Decodes encoded value to Date.
     * @param encodedValidity a relative time string (SimpleTime) or a date in ISO8601 format.
     * @param firstDate date to be used if encoded validity is a relative time.
     * @return the end date.
     * @see org.cesecore.util.SimpleTime
     * @see org.cesecore.util.ValidityDate
     */
	public static Date getDate(final String encodedValidity, final Date firstDate) {
	    try {
	        return parseAsIso8601(encodedValidity);
	    } catch(ParseException p) {
	        try {
	            final long millis = SimpleTime.parseMillies(encodedValidity);
	            final Date endDate = new Date(firstDate.getTime() + millis);
	            return endDate;
	        } catch(NumberFormatException nfe) {
	            log.error("Could not read encoded validity: " + nfe.getMessage(), nfe);
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
	 * Parse a date as either "yyyy-MM-dd HH:mm:ssZZ" or a relative hex encoded UNIX time stamp (in seconds).
	 * Use for parsing of the build time property "ca.toolateexpiredate" in ejbca.properties.
	 * @return the date or the largest possible Date if unable to parse the argument.
	 */
	public static Date parseCaLatestValidDateTime(final String sDate) {
		Date tooLateExpireDate = null;
        if (sDate.length()>0) {
        	//First, try to parse the date in ISO8601 date time format.
    		try {
    			return parseAsIso8601(sDate);
    		} catch (ParseException e) {
        		log.debug("tooLateExpireDate could not be parsed as an ISO8601 date: " + e.getMessage());
    		}
    		// Second, try to parse it as a hexadecimal value (without markers of any kind.. just a raw value).
            if (tooLateExpireDate == null) {
            	try {
            		tooLateExpireDate = new Date(Long.parseLong(sDate, 16)*1000);
            	} catch (NumberFormatException e) {
            		log.debug("tooLateExpireDate could not be parsed as a hex value: " + e.getMessage());
            	}
            }
        }
        if (tooLateExpireDate == null) {
        	log.debug("Using default value for ca.toolateexpiredate.");
            tooLateExpireDate = new Date(Long.MAX_VALUE);
        } else if (log.isDebugEnabled()) {
        	log.debug("tooLateExpireData is set to: "+tooLateExpireDate);
        }
        return tooLateExpireDate;
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
}
