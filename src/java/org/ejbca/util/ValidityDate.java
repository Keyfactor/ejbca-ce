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

import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import org.apache.log4j.Logger;

/**
 * Class for encoding and decoding certificate validity and end date.
 * 
 * @author lars
 * @version $Id$
 */
public class ValidityDate {
	final private static Logger log = Logger.getLogger(ValidityDate.class);
	final private static Locale defaultLocale = Locale.getDefault();
	final private static int dateStyle = DateFormat.SHORT;
	final private static int timeStyle = DateFormat.MEDIUM;
	final private static DateFormat defaultDateFormat = DateFormat.getDateTimeInstance(dateStyle, timeStyle);
	final private static TimeZone utcTimeZone = TimeZone.getTimeZone("UTC");
	static {
		defaultDateFormat.setTimeZone(utcTimeZone);
	}

	/**
	 * This method tries to use a date string to get a {@link java.util.Date} object.
	 * Different ways of getting the date is tried. If one is not working the next is tried:
	 * 1. We just assume that the input is a hex string encoded in seconds since epoch (the Unix time).
	 * 2. The default local is used to try to decode the date in {@link java.text.DateFormat#SHORT} format and time in {@link java.text.DateFormat#MEDIUM} format. Time zone 'UTC' is used.
	 * 3. All available locales are tried until one works. Decoding done the same way as 2
	 * @param sDate the encoded date.
	 * @return the date decoded from 'sDate'. null if no decoding can be done.
	 */
	public static Date getDateFromString(String sDate) {

		try {
			final Date date = defaultDateFormat.parse(sDate);
			if ( date!=null ) {
				log.debug("Date string '"+sDate+"' with default local '"+defaultLocale.getDisplayName()+"' gives '"+date+"' when decoded." );
				return date;
			}
		} catch (ParseException e1) {
			// just try next
		}
		log.debug("The default locale '"+defaultLocale.getDisplayName()+"' can not decode the date string '"+sDate+"'.");
		final Locale[] locales=DateFormat.getAvailableLocales();
		for ( int i=0; i<locales.length; i++) {
			final Locale locale = locales[i];
			try {
				final DateFormat dateFormat = DateFormat.getDateTimeInstance(dateStyle, timeStyle, locale);
				dateFormat.setTimeZone(utcTimeZone);
				final Date date = dateFormat.parse(sDate);
				if ( date!=null ) {
					log.warn("Default local '"+defaultLocale.getDisplayName()+"' not possible to use. Date string '"+sDate+"' in locale '"+locale.getDisplayName()+"' gives '"+date+"' when decoded. This date will be used. To use the default locale '"+defaultLocale.getDisplayName()+"' specify the date as '"+defaultDateFormat.format(date)+"'." );
					return date;
				}
			} catch (ParseException e1) {
				// just try next
			}
			log.debug("Locale '"+locale.getDisplayName()+"' can not decode the date string '"+sDate+"'.");
		}
		final Date exampleDate=new Date();
		log.info("Not possible to decode the date '"+sDate+"'. Example: The date '"+exampleDate+"' should be encoded as '"+defaultDateFormat.format(exampleDate)+"' in the default local '"+defaultLocale.getDisplayName()+"'.");
		return null;
	}
	/**
	 * Encoding of the validity for a CA. Either delta time or end date.
	 * @param sValidity h*m*d* or valid date string in current locale.
	 * @return delta time in days if h*m*d*; milliseconds since epoch if valid thate; -1 if neither
	 */
	public static long encode(String sValidity) {
		try {
			// First try with decimal format (days)
			return Integer.parseInt(sValidity);
		} catch(NumberFormatException ex) {
			// Use '*y *mo *d'-format
		}
		YearMonthDayTime ymod = YearMonthDayTime.getInstance(sValidity, "0"+YearMonthDayTime.TYPE_DAYS);
		if ( ymod!=null ) {
			return (int) ymod.daysFrom(new Date());
		}
		final Date date = getDateFromString(sValidity);
		if ( date!=null ) {
			return date.getTime();
		}
		return -1;
	}
	private static boolean isDeltaTime(long lEncoded) {
		return lEncoded < Integer.MAX_VALUE;
	}
	/**
	 * decodes encoded value to string.
	 */
	public static String getString(long lEncoded) {
		if ( isDeltaTime(lEncoded) ) {
			return "" + lEncoded + YearMonthDayTime.TYPE_DAYS;
		}
		return defaultDateFormat.format(new Date(lEncoded));
	}
	/**
	 * Decodes encoded value to Date.
	 * @param lEncoded encoded value
	 * @param firstDate date to be used if encoded value is a delta time.
	 */
	public static Date getDate(long lEncoded, Date firstDate) {
		if ( isDeltaTime(lEncoded) ) {
			return new Date(firstDate.getTime() + ( lEncoded * 24 * 60 * 60 * 1000));
		}
		return new Date(lEncoded);
	}
	/**
	 * To be used when giving format example.
	 * @return locale name and current date.
	 */
	public static String getDateExample() {
		return "(" + defaultLocale.getDisplayName() + "): '" +  defaultDateFormat.format(new Date()) + "'.";
	}
}
