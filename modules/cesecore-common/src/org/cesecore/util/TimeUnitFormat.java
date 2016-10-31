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

package org.cesecore.util;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

/** 
 * Class to parse and format relative time values, i.e. '1y-2mo+3d-4h+5m-6s7ms'.
 *  
 * @version $Id: TimeUnitFormat.java 22133 2016-10-01 10:20:32Z anjakobs $
 */
public final class TimeUnitFormat {
    
    private static final String PATTERN_PREFIX = "\\s*(([+-]?\\d+)\\s*(";
    private static final String PATTERN_SUFFIX = "))\\s*";
    private static final String ZERO = "0";
    private static final String SPACE = " ";
    private static final String OR = "|";
    private static final String OPENING_BRAKET = "[";
    private static final String CLOSING_BRAKET = "]";

    private static final String EXCEPTION_MESSAGE_ILLEGAL_CHARACTERS = "Illegal characters.";
    private static final String EXCEPTION_MESSAGE_BLANK_STRING = "Cannot parse a blank string.";
    
    private Pattern pattern;
    private Map<String, Long> defaultValues;
    private Map<String, Long> factors;
    private List<String> units;

    /**
     * Instantiates a new TimeUnitFormat and initializes it with the given units.
     * @param units List of units (suffixes, i.e. 'ms', 'mo', 'y', 'd', 'h', 'm', and 's').
     */
    public TimeUnitFormat(final List<String> units, final Map<String, Long> factors) {
        this.units = units;
        this.factors = factors;
        this.defaultValues = new LinkedHashMap<String, Long>(units.size());
        final StringBuilder builder = new StringBuilder(PATTERN_PREFIX);
        int index = 0;
        for (String unit : units) {
            this.defaultValues.put(unit.toLowerCase(), 0L);
            if (index++ > 0) {
                builder.append(OR);
            }
            for (char c : unit.toCharArray()) {
                builder.append(OPENING_BRAKET).append(Character.toLowerCase(c)).append(CLOSING_BRAKET);
            }
        }
        builder.append(PATTERN_SUFFIX);
        pattern = Pattern.compile(builder.toString(), Pattern.CASE_INSENSITIVE);
    }

    /**
     * Parses a formatted time string.
     * 
     * @param formatted
     *            time string, i.e '1y-2mo10d'.
     * @return the milliseconds as long value from 0.
     * @throws ParseException
     *             if the string cannot be parsed, i.e. it contains units not
     *             listed or other illegal characters or forms.
     */
    public long parseMillis(String formattedString) throws NumberFormatException {
        NumberFormatException exception = null;
        long result = 0;
        if (StringUtils.isNotBlank(formattedString)) {
            formattedString = formattedString.trim();
            final Matcher matcher = pattern.matcher(formattedString);
            long parsedValue;
            String unit = null;
            int start = 0, end = 0;
            while (matcher.find()) {
                start = matcher.start();
                if (start != end) {
                    exception = new NumberFormatException(EXCEPTION_MESSAGE_ILLEGAL_CHARACTERS);
                    break;
                }
                end = matcher.end();
                for (int i = 0; i < matcher.groupCount(); i = i + 3) {
                    parsedValue = Long.parseLong(matcher.group(i + 2));
                    unit = matcher.group(i + 3).toLowerCase();
                    result += factors.get(unit) * parsedValue;
                }
            }
            if (end != formattedString.length()) {
                exception = new NumberFormatException(EXCEPTION_MESSAGE_ILLEGAL_CHARACTERS);
            }

        } else {
            exception = new NumberFormatException(EXCEPTION_MESSAGE_BLANK_STRING);
        }
        if (null != exception) {
            throw exception;
        }
        return result;
    }

    /**
     * Formats the given period in milliseconds to a readable string.   
     * @param millis the milliseconds (count from 0 - not epoch).
     * @param zeroType the unit if the result is 0.
     * @return a readable string in form of the ordered value unit pairs (*y *mo *d *h *m *s), separated by white space character. Milliseconds are lost.
     */
    public String format(final long millis, final Map<String, Long> factors, final String zeroType) {
        long value = millis;
        String unit = null;
        long factor = 0;
        long currentValue = 0;
        final StringBuilder builder = new StringBuilder();
        for (Entry<String,Long> entry : factors.entrySet()) {
            unit = entry.getKey();
            if (units.contains(unit)) {
                factor = entry.getValue();
                currentValue = value / factor;
                value %= factor;
                if (currentValue != 0) {
                    if (builder.length() > 0) {
                        builder.append(SPACE);
                    }
                    builder.append(Long.toString(currentValue)).append(unit);
                }
            }
        }
        if (builder.length() < 1) {
            builder.append(ZERO).append(zeroType);
        }
        return builder.toString();
    }
}
