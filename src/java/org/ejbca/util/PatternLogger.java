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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;

import org.apache.log4j.Logger;

/**
 * This class can be extended to create highly configurable log classes.
 * Values that are to be logged are stored in a Hashmap and the output is configured using a Java.util.regex.Matcher and a sortString.
 * The extending classes also need to supply a Logger and a String specifying how to log Dates.
 * 
 * Use paramPut(String key, String value) to add values,
 * Use writeln() to logg all the stored values and then use flush() to store them to file.
 * 
 * @author thamwickenberg
 * @version $Id$
 */
public abstract class PatternLogger { 
	public static final String LOG_TIME="LOG_TIME";// The Date and time the request.
	protected HashMap valuepairs= new HashMap();
	private StringBuffer logmessage = new StringBuffer();
	private Matcher m;
	private String orderString;
	private Logger logger;
	private String logDateFormat;
	
	/**
	 * 
	 * @param m A matcher that is used together with orderstring to determine how output is formatted
	 * @param orderString A string that matches the pattern in m and specifies the order in which values are logged by the logger
	 * @param logger A log4j Logger that is used for output
	 * @param logDateFormat A string that specifies how the log-time is formatted
	 */
	public PatternLogger(Matcher m, String orderString, Logger logger, String logDateFormat) {
		this .m = m;
		this.orderString=orderString;
		this.logger = logger;
		this.logDateFormat = logDateFormat;
	}
	
	/**
	 * 
	 * @return output to be logged
	 */
	protected  String interpolate() {
		final StringBuffer sb = new StringBuffer(orderString.length());
		m.reset();
		while (m.find()) {
			// when the pattern is ${identifier}, group 0 is 'identifier'
			String key = m.group(1);
			String value = (String)valuepairs.get(key);

			// if the pattern does exists, replace it by its value
			// otherwise keep the pattern ( it is group(0) )
			if (value != null) {
				m.appendReplacement(sb, value);
			} else {
				// I'm doing this to avoid the backreference problem as there will be a $
				// if I replace directly with the group 0 (which is also a pattern)
				m.appendReplacement(sb, "");
				String unknown = m.group(0);
				sb.append(unknown);
			}
		}
		m.appendTail(sb);
		return sb.toString();
	}

	protected void cleanParams() {
		DateFormat dateformat = new SimpleDateFormat(logDateFormat); 
		paramPut(LOG_TIME, dateformat.format(new Date()));
	}
	/**
	 * method that makes sure that a "" is inserted instead of null
	 * @param key
	 * @param value
	 */
	public void paramPut(String key, String value){
		//logger.debug("paramput: "+ key+ ";" +value +";" +valuepairs.toString());
		if(value == null){
			valuepairs.put(key, "");
		}else{
			valuepairs.put(key, value);
		}	  
	}

	/**
	 * method that makes sure that a "" is inserted instead of null
	 * @param key
	 * @param value
	 */
	public void paramPut(String key, Integer value){
		if(value == null){
			valuepairs.put(key, "");
		}else{
			valuepairs.put(key, value.toString());
		}
	}

	/**
	 * Method used to retrieve the populated parameter hashmap with the notification text.
	 * @return
	 */
	public HashMap getParams(){
		return valuepairs;
	}
	
	/**
	 * Method used for creating a log row of all added values
	 */
	public void writeln() {
		logmessage.append(interpolate()+"\n");
	}
	
	/**
	 * Writes all the rows created by writeln() to the Logger
	 */
	public void flush() {
		String logstring = logmessage.toString();
		logger.debug(logstring);
	}
}
