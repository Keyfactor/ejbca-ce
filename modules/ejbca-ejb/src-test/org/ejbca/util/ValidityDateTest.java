package org.ejbca.util;

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.time.FastDateFormat;

import junit.framework.TestCase;

public class ValidityDateTest extends TestCase {

	private String[] timePatterns = {"yyyy-MM-dd HH:mm"};
	private FastDateFormat fastDateFormat = FastDateFormat.getInstance(timePatterns[0]);
	
    public ValidityDateTest(String name) { super(name); }

    public void setUp() throws Exception { }
    public void tearDown() throws Exception { }

	public void test01ParseStringDates() {
		
		Date date = new Date();
		String dateStr = fastDateFormat.format(date);
		assertEquals(date.getTime(), ValidityDate.encode(dateStr));
		
		
		// TODO add code to test a period in the format *y *mo *d
		
		// parsing time in hex vs decimal formats
		// In hex, 80000000 represent the year 2038. See the documentation of ca.toolateexpiredate in ejbca.properties file
		String hexTime = "80000000";
		assertEquals(Long.parseLong(hexTime), ValidityDate.encode(hexTime));
		assertNull(ValidityDate.getDateFromString(hexTime));

		date = new Date(ValidityDate.encode(hexTime));
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
