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
 
package se.anatom.ejbca.util;

import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * This class implements some utility functions that are useful when handling Strings.
 *
 * @version $Id: StringTools.java,v 1.24 2005-06-20 07:47:56 anatom Exp $
 */
public class StringTools {
    private static Logger log = Logger.getLogger(StringTools.class);

    // Characters that are not allowed in strings that may be stored in the db
    private static final char[] stripChars = {
        '\"', '\n', '\r', '/', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?',
        '$', ':', '~'
    };
    // Characters that are not allowed in strings that may be used in db queries
    private static final char[] stripSqlChars = {
        '\'', '\"', '\n', '\r', '/', '\\', ';', '&', '|', '!', '\0', '%', '`', '<', '>', '?',
        '$', ':', '~'
    };
    // Characters that are allowed to escape in strings
    private static final char[] allowedEscapeChars = {
        ','
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
                // If it is an escape char, we have to process manually
                if (stripChars[i] == '\\') {
                    // If it is an escaped char, allow it if it is an allowed escapechar
                    int index = ret.indexOf('\\');
                    while (index > -1) {
                    	if (isAllowed(ret.charAt(index+1))) {
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
     * Checks if a string contains characters that would be stripped by 'strip'
     *
     * @param str the string whose contents would be stripped.
     * @return true if some chars in the string would be stripped, false if not.
     * @see #strip
     */
    public static boolean hasSqlStripChars(String str) {
        if (str == null) {
            return false;
        }
        String ret = str;
        for (int i = 0; i < stripSqlChars.length; i++) {
            if (ret.indexOf(stripSqlChars[i]) > -1) {
                // If it is an escape char, we have to process manually
                if (stripSqlChars[i] == '\\') {
                    // If it is an escaped char, allow it if it is an allowed escapechar
                    int index = ret.indexOf('\\');
                    while (index > -1) {
                        if (isAllowed(ret.charAt(index+1))) {
                            return true;
                        }
                        index = ret.indexOf('\\',index+1);
                    }
                } else {
                    return true;
                }
            }
        }
        return false;
    } // hasSqlStripChars

    /** Checks if a character is an allowed escape characted according to allowedEscapeChars
     * 
     * @param ch the char to check
     * @return true if char is an allowed escape character, false if now
     */ 
    private static boolean isAllowed(char ch) {
    	boolean allowed = false;
    	for (int j = 0; j < allowedEscapeChars.length; j++) {
    		if (ch == allowedEscapeChars[j]) {
    			allowed = true;
    			break;
    		}
    	}
    	return allowed;
    }
    
    /**
     * Strips all whitespace including space, tabs, newlines etc from the given string.
     *
     * @param str the string
     * @return the string with all whitespace removed
     * @since 2.1b1
     */
    public static String stripWhitespace(String str) {
        if (str == null) {
            return null;
        }
        return WS.matcher(str).replaceAll("");
    }
    
    /** Converts an IP-address string to octets of binary ints. 
     * ip is of form a.b.c.d, i.e. at least four octets
     * @param str string form of ip-address
     * @return octets, null if input format is invalid
     */
    public static byte[] ipStringToOctets(String str) {
        String[] toks = str.split("[.:]");
        if (toks.length == 4) {
            // IPv4 address
            byte[] ret = new byte[4];
            for (int i = 0;i<toks.length;i++) {
                int t = Integer.parseInt(toks[i]);
                if (t>255) {
                    log.error("IPv4 address '"+str+"' contains octet > 255.");
                    return null;
                }
                ret[i] = (byte)t;
            }
            return ret;
        }
        if (toks.length == 8) {
            // IPv6 address
            byte[] ret = new byte[16];
            int ind = 0;
            for (int i = 0;i<toks.length;i++) {
                int t = Integer.parseInt(toks[i]);
                if (t>0xFFFF) {
                    log.error("IPv6 address '"+str+"' contains part > 0xFFFF.");
                    return null;
                }
                int b1 = t & 0x00FF;
                ret[ind++] = (byte)b1;
                int b2 = t & 0xFF00;
                ret[ind++] = (byte)b2;
            }
        }
        log.error("Not a IPv4 or IPv6 address.");
        return null;
    }
} // StringTools
