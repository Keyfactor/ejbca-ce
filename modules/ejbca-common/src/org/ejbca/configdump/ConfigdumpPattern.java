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
package org.ejbca.configdump;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.ejbca.configdump.ConfigdumpSetting.ItemType;

/**
 * A simple pattern that supports "*" only (unlike Pattern which allows full regexes)
 * and that keeps track of the number of matches.
 * 
 * @version $Id$
 */
public class ConfigdumpPattern implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private final String patternString;
    private final Pattern pattern;
    private int numMatches = 0;
    
    public ConfigdumpPattern(final String simplePattern) {
        // Convert "basic" pattern with only "*" wildcards into a regex
        // The string is "quoted" (avoids parsing as regex) except for * which are translated into \E.*\Q
        // \E and \Q are the escape sequences to stop- and start quoting respectively
        pattern = Pattern.compile('^'+Pattern.quote(simplePattern).replace("*", "\\E.*\\Q").replace("\\Q\\E", "")+'$');
        patternString = simplePattern;
    }
    
    public boolean matches(final CharSequence input) {
        if (pattern.matcher(input).find()) {
            numMatches++;
            return true;
        }
        return false;
    }
    
    public int getNumMatches() {
        return numMatches;
    }
    
    @Override
    public String toString() {
        return patternString;
    }
    
    /**
     * Parses an --include or --exclude argument. The syntax is:
     *
     * TYPE1:NAME_PATTERN1; TYPE2:NAME_PATTERN2
     *
     * The type may be a "*", indicating any type. The name pattern may contain *, indicating any sequence of
     * characters.
     * @throws IllegalWildCardSyntaxException
     */
    public static void parseIncludeExcludeString(final Map<ItemType, List<ConfigdumpPattern>> matchMap, final List<ConfigdumpPattern> matchAnyTypeList,
            final String arg) throws IllegalWildCardSyntaxException {

        if (arg == null || arg.isEmpty()) {
            return;
        }

        final String[] entries = arg.split(";");
        for (String entry : entries) {
            entry = entry.trim();
            if (entry.isEmpty()) {
                continue;
            }

            final String[] pieces = entry.split(":", 2);
            if (pieces.length != 2) {
                throw new IllegalWildCardSyntaxException(
                        "Missing ':' in include or exclude entry \"" + entry + "\". Usage examples: ca:*, *:Example, *:*");
            }
            final String typeStr = pieces[0].trim().toUpperCase();
            final String patternStr = pieces[1].trim().toLowerCase();
            final ConfigdumpPattern pattern = new ConfigdumpPattern(patternStr);
            if (typeStr.equals("*")) {
                matchAnyTypeList.add(pattern);
            } else if (StringUtils.isEmpty(typeStr)) {
                throw new IllegalWildCardSyntaxException("Incorrect syntax: No type was defined before the colon in " + entry);
            } else {
                final ItemType type;
                try {
                    type = Enum.valueOf(ItemType.class, typeStr);
                } catch (IllegalArgumentException e) {
                    throw new IllegalWildCardSyntaxException("Incorrect type '" + typeStr + "'. Must be one of " + StringUtils.join(ItemType.values(), ", "));
                }
                if (!matchMap.containsKey(type)) {
                    matchMap.put(type, new ArrayList<ConfigdumpPattern>());
                }
                matchMap.get(type).add(pattern);
            }
        }
    }

    public static class IllegalWildCardSyntaxException extends Exception {
        private static final long serialVersionUID = 1L;

        public IllegalWildCardSyntaxException(String message) {
            super(message);
        }

    }
}
