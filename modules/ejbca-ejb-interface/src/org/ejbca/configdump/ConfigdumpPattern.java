/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.configdump;

import java.io.Serializable;
import java.util.regex.Pattern;

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
}
