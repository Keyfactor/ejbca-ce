package se.anatom.ejbca.util;

import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.15 2004-01-28 10:39:11 herrvendil Exp $
 */
public class StringTools {
    private static Logger log = Logger.getLogger(StringTools.class);

    // Characters that are bynot allowed in strings that may be passed to the db
    private static final char[] stripChars = {
        '\'', '\"', '\n', '\r', '/', '\\', ';', '&', '|', '!', '\0', '%', '`', '?', '<', '>', '?',
        '$', ':', '~'
    };
    // Characters that are allowed to escape in strings
    private static final char[] allowedEscapeChars = {
        ','
    };
    
    private static  Pattern[] escapepatterns = null;
    
    private static final Pattern WS = Pattern.compile("\\s+");

    /**
     * Strips all special characters from a string by replacing them with a forward slash, '/'.
     *
     * @param str the string whose contents will be stripped.
     *
     * @return the stripped version of the input string.
     */
    public static String strip(String str) {
        if (str == null) {
            return null;
        }

        String ret = str;

        for (int i = 0; i < stripChars.length; i++) {
            if (ret.indexOf(stripChars[i]) > -1) {
                // If it is an escape char, we have to process manually
                if (stripChars[i] == '\\') {
                    // If it is an escaped char, allow it if it is an allowed escapechar
                    int index = ret.indexOf('\\');
                    while (index > -1) {
                        boolean allowed = false;
                        for (int j = 0; j < allowedEscapeChars.length; j++) {
                            if (ret.charAt(index+1) == allowedEscapeChars[j]) {
                                allowed = true;
                            }
                        }
                        if (!allowed) {
                            StringUtils.overlay("abcdef", "zzzz", 2, 4);
                            ret = StringUtils.overlay(ret,"/",index,index+1);
                        }
                        index = ret.indexOf('\\',index+1);
                    }
                } else {
                    ret = ret.replace(stripChars[i], '/');
                }
            }
        }
        return ret;
    } // strip

    
    /**
     * Strips all whitespace including space, tabs, newlines etc from the given string.
     *
     * @param str the string
     *
     * @return the string with all whitespace removed
     *
     * @since 2.1b1
     */
    public static String stripWhitespace(String str) {
        if (str == null) {
            return null;
        }

        return WS.matcher(str).replaceAll("");
    }
} // StringTools
