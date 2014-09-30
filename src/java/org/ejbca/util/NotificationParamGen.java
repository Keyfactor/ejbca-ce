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

import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cesecore.util.ValidityDate;

/**
 * Base class generating parameter data for email notifications. Derived classes can add additional parameters.
 * 
 * The following parameters are set in this class
 * ${NL}                           = New Line in message
 * ${DATE} or ${current.DATE}      = The current date
 * 
 *
 * @version $Id$
 */

public class NotificationParamGen {

  private HashMap<String, String> params = new HashMap<String, String>();	
  
  /** regexp pattern to match ${identifier} patterns */
  private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
  
  protected NotificationParamGen() {
	  paramPut("NL", System.getProperty("line.separator"));
      paramPut("DATE", fastDateFormat(new Date()));
  }

  /**
   * Method used to retrieve the populated parameter HashMap with the notification text.
   */
  public HashMap<String, String> getParams(){
	  return params;
  }

  /**
   * method that makes sure that a "" is inserted instead of null
   * @param key
   * @param value
   */
  protected void paramPut(String key, String value){
	  if(value == null){
		  params.put(key, "");
	  }else{
		  params.put(key, value);
	  }
  }
  
  /**
   * method that makes sure that a "" is inserted instead of null
   * @param key
   * @param value
   */
  protected void paramPut(String key, Integer value){
	  if(value == null){
		  params.put(key, "");
	  }else{
		  params.put(key, value.toString());
	  }
  }
	
  // Help method used to populate a message 
  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  public String interpolate(String input) {
	  return interpolate(getParams(), input);
  }

  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  public static String interpolate(HashMap<String, String> patterns, String input) {
      final Matcher m = PATTERN.matcher(input);
      final StringBuffer sb = new StringBuffer(input.length());
      while (m.find()) {
          // when the pattern is ${identifier}, group 0 is 'identifier'
          String key = m.group(1);
          String value = patterns.get(key);
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
  
  protected String fastDateFormat(Date date) {
	  return ValidityDate.formatAsISO8601(date, ValidityDate.TIMEZONE_SERVER);
  }
}
