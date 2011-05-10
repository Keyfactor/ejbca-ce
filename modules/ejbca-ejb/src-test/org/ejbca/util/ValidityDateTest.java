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

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.time.FastDateFormat;

import junit.framework.TestCase;

/**
 * @version $Id$
 */
public class ValidityDateTest extends TestCase {

	private String[] timePatterns = {"yyyy-MM-dd HH:mm"};
	private FastDateFormat fastDateFormat = FastDateFormat.getInstance(timePatterns[0]);
	
    public ValidityDateTest(String name) { super(name); }

    public void setUp() throws Exception { }
    public void tearDown() throws Exception { }

	public void test01ParseStringDates() {
		
		// TODO add code to test a period in the format *y *mo *d
		
		// parsing time in hex vs decimal formats
		// In hex, 80000000 represent the year 2038. See the documentation of ca.toolateexpiredate in ejbca.properties file
		String hexTime = "80000000";
		assertEquals(Long.parseLong(hexTime), ValidityDate.encode(hexTime));
		assertNull(ValidityDate.getDateFromString(hexTime));

		Date date = new Date(ValidityDate.encode(hexTime));
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		assertNotSame(2038, calendar.get(Calendar.YEAR));
		
		hexTime = "COFFEE";
		assertEquals(-1, ValidityDate.encode(hexTime));
		assertNull(ValidityDate.getDateFromString(hexTime));
	}
	
	public void test02FormatStringDates() {
		Date date = new Date();
		String dateStr = fastDateFormat.format(date);
		assertEquals(dateStr, ValidityDate.getString(date.getTime()));
	}
	
	
}
