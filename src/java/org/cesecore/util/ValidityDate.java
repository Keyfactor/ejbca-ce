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
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;

/**
 * Class for encoding and decoding certificate validity and end date.
 * 
 * Based on EJBCA version: 
 *      ValidityDate.java 8797 2010-03-24 13:37:19Z anatom
 * Based on CESeCore version:
 *      ValidityDate.java 850 2011-05-20 15:01:44Z johane
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
	private static final String[] ISO8601_PATTERNS = {ISO8601_DATE_FORMAT};
	
	/** Parse a String in the format "yyyy-MM-dd HH:mm" as a date with implied TimeZone UTC. */
	public static Date parseAsUTC(final String dateString) throws ParseException {
		return DateUtils.parseDateStrictly(dateString+"+00:00", IMPLIED_UTC_PATTERN_TZ);
	}

	/** Parse a String in the format "yyyy-MM-dd HH:mm:ssZZ". */
	public static Date parseAsIso8601(final String dateString) throws ParseException {
		return DateUtils.parseDateStrictly(dateString, ISO8601_PATTERNS);
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
	 * @param sValidity *y *mo *d or absolute date in the form "yyyy-MM-dd HH:mm:ssZZ"
	 * @return delta time in days if h*m*d*; milliseconds since epoch if valid absolute date; -1 if neither
	 */
	public static long encode(final String sValidity) {
		long returnValue = -1;
		// Try '*y *mo *d'-format
		final YearMonthDayTime yearMonthDayTime = YearMonthDayTime.getInstance(sValidity, "0"+YearMonthDayTime.TYPE_DAYS);
		if (yearMonthDayTime!=null) {
			long days = yearMonthDayTime.daysFrom(new Date());
			if (isDeltaTime(days)) {
				returnValue = days;
			} else {
				returnValue = Long.valueOf(Integer.MAX_VALUE-1);
				log.info(sValidity + " was parsed as a relative time, but is too far in the future. Limiting to " + returnValue + " days.");
			}
		} else {
			// Try to parse the time in the format yyyy-MM-dd HH:mm:ssZZ
			try {
				returnValue = parseAsIso8601(sValidity).getTime();
			} catch (ParseException e) {
				if (log.isDebugEnabled()) {
					final Date exampleDate = new Date();
					log.debug("Not possible to decode the date '"+sValidity+"'. Example: The date '"+exampleDate+"' should be encoded as '"+formatAsUTC(exampleDate)+"'");
				}
			}
		}
		return returnValue;
	}

	/**
	 * Decodes encoded value to string in the form "yyyy-MM-dd HH:mm:ssZZ" or "1234d" (relative days).
	 * @param lEncoded If this is below Integer.MAX_VALUE it is interpreted as a number of days to firstDate, otherwise an unix timestamp.
	 */
	public static String getString(final long lEncoded) {
		if (isDeltaTime(lEncoded)) {
			return "" + lEncoded + YearMonthDayTime.TYPE_DAYS;
		}
		return formatAsISO8601ServerTZ(lEncoded, TIMEZONE_SERVER);		
	}
	
	/**
	 * Decodes encoded value to Date.
	 * @param lEncoded encoded value. If this is below Integer.MAX_VALUE it is interpreted as a number of days to firstDate, otherwise an unix timestamp.
	 * @param firstDate date to be used if encoded value is a delta time. Can never be null.
	 */
	public static Date getDate(final long lEncoded, final Date firstDate) {
		if ( isDeltaTime(lEncoded) ) {
			return new Date(firstDate.getTime() + ( lEncoded * 24 * 60 * 60 * 1000));
		}
		return new Date(lEncoded);
	}

	/** If below the integer capacity we have stored a relative date in days, otherwise it is an absolute time in milliseconds. */
	private static boolean isDeltaTime(final long lEncoded) {
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
}
