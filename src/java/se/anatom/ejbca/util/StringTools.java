package se.anatom.ejbca.util;

import java.util.regex.Pattern;


/**
 * This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.11 2003-07-24 08:43:32 anatom Exp $
 */
public class StringTools {
    private static final char[] stripChars = {
        '\'', '\"', '\n', '\r', '/', '\\', ';', '&', '|', '!', '\0', '%', '`', '?', '<', '>', '?',
        '$', ':', '~'
    };
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
                ret = ret.replace(stripChars[i], '/');
            }
        }

        return ret;
    }

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
}


// StringTools
