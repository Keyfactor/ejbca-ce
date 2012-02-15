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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for performing parsing of inputs containing units.
 * 
 * The format is in the form '*unit1 *unit2 *unit3' and so on where * is a 
 * decimal number and the units are specified in the constructor. 
 * Spaces are optional. Units are case-insensitive.
 *  
 * Based on UnitParser.java 124 2011-01-20 14:41:21Z tomas from cesecore,
 * 
 * @version $Id$
 * @see SimpleTime
 * @see YearMonthDayTime
 */
public class UnitParser {
	
	private static final Pattern valuePattern = Pattern.compile("(\\d+)");
	private static final Pattern typePattern = Pattern.compile("(\\D+)");

	private Pattern pattern;
    private Map<String, Long> defaultValues;
    
    /**
     * Constructs a new UnitParser and initializes it with the given units.
     * @param units List of units (suffixes)
     */
    public UnitParser(List<String> units) {
    	defaultValues = new LinkedHashMap<String, Long>(units.size());
    	StringBuilder sb = new StringBuilder();
    	sb.append("^");
    	for(Object o : units) {
    		String unit = (String) o;
    		defaultValues.put(unit.toLowerCase(), Long.valueOf(0));
    		sb.append("(\\d+");
    		for(char c : unit.toCharArray()) {
    			sb.append("[");
    			sb.append(Character.toLowerCase(c));
    			sb.append(Character.toUpperCase(c));
    			sb.append("]");
    		}
    		sb.append(")?");
    	}
    	sb.append("$");
    	pattern = Pattern.compile(sb.toString());
    }

	/**
	 * Parse string and convert it using this object's specified units.
	 * @param time AdBhCmDsEu could for instance mean A days, B hours, C minutes, D seconds and E milliseconds
	 * @throws NumberFormatException if an parsing error occurs
	 * @throws IllegalArgumentException if time is empty (or only contains white-spaces)
	 * @throws NullPointerException if time is null
	 */
	public Map<String, Long> parse(String time) throws NumberFormatException {
		Map<String, Long> values = new LinkedHashMap<String, Long>(defaultValues);
		if (time == null) {
			throw new NullPointerException("Time is null.");
		}
		time = time.replaceAll("\\s", "");	// Remove all white-spaces
		if (time.length() == 0) {
			throw new IllegalArgumentException("Time is empty.");
		}
		Matcher matcher = pattern.matcher(time);
		if (!matcher.find()) {
			throw new NumberFormatException("Not a match.");
		}
		
		for (int i = 0; i < matcher.groupCount(); i++) {
			String match = matcher.group(i+1);
			if (match != null) {
				Matcher valueMatcher = valuePattern.matcher(match);
				Matcher typeMatcher = typePattern.matcher(match);
				if (!valueMatcher.find() || !typeMatcher.find()) {
					throw new NumberFormatException("Not a match.");
				}
				long value = Long.parseLong(valueMatcher.group(1));
				String type = typeMatcher.group(1).toLowerCase();
				values.put(type, Long.valueOf(value));
			}
		}
		return values;
	}
	
	/**
	 * @param values Map with the units and the values to print.
	 * @param zeroType the unit of the returned value if '0'.
	 * @return time in the format Aa Bb Cc and so on meaning A with unit a, 
	 * B with unit b and C with unit c and so on.
	 */
	public String toString(Map<String, Long> values, String zeroType) {
		StringBuilder sb = new StringBuilder();
		//for(Map.Entry<String, Long> entry : values.entrySet()) {
		for(Map.Entry<String, Long> o : values.entrySet()) {
			Map.Entry<String, Long> entry = o;
			if(entry.getValue() != 0) {
				if(sb.length() != 0) {
					sb.append(" ");
				}
				sb.append(entry.getValue());
				sb.append(entry.getKey());
			}
		}
		if(sb.length() == 0) {
			sb.append("0");
			sb.append(zeroType);
		}
		return sb.toString();
	}
}
