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
package org.ejbca.util.dn;

import org.apache.log4j.Logger;

/**
 * DN string utilities.
 * 
 * Optimized to lower object instantiation by performing manipulations "in-place" using StringBuilder and char[].
 * 
 * Not built to handle '+' char separators or take special consideration to Unicode.
 * 
 * @author primelars
 * @version $Id$
 */
public abstract class DNFieldsUtil {

	private static final Logger LOG = Logger.getLogger(DNFieldsUtil.class);
	private static final String MSG_ERROR_MISSING_EQUAL = "DN field definition is missing the '=': ";

	/**
	 * Removes all fields (key=value) where the value is empty.
	 * Example: "CN=abc,CN=,CN=def,O=,O=abc,O=" will become "CN=abc,CN=def,O=abc".
	 * @param sDN the String to clean.
	 * @return a copy of the String where all fields with empty values have been removed.
	 */
    public static String removeAllEmpties(final String sDN) {
    	final char[] buf = sDN.toCharArray();
    	final StringBuilder sb = new StringBuilder(buf.length);
    	int lastPairStartPos = 0;
    	int lastEqualPos = 0;
    	boolean notEscaped = true;
    	for (int i=0; i<buf.length-1; i++) {
    		switch (buf[i]) {
    		case '\\':
    			notEscaped ^= true;	// Keep track of what is escapes and not
    			break;
    		case ',':
    			if (notEscaped) {
    				// If last char was '=' this value was empty and should not be included in the result
    				if (lastEqualPos != i-1) {
    					if (lastEqualPos <= lastPairStartPos) {
    		    			LOG.info(MSG_ERROR_MISSING_EQUAL + sDN);
    		    			return null;
    					}
    					sb.append(buf, lastPairStartPos, i+1-lastPairStartPos);
    				}
    				lastEqualPos = 0;
    				lastPairStartPos = i+1;
    			}
    			break;
    		case '=':
    			if (notEscaped) {
    				lastEqualPos = i;
    			}
    			break;
    		default:
    			notEscaped=true;
    		}
    	}
    	// If last char was '=' this value was empty and should not be included in the result
    	if (lastEqualPos != buf.length-1) {
    		if (lastEqualPos <= lastPairStartPos) {
    			LOG.info(MSG_ERROR_MISSING_EQUAL + sDN);
    			return null;
    		}
    		sb.append(buf, lastPairStartPos, buf.length-lastPairStartPos);
    	}
    	return sb.toString();
    }

	/**
	 * Removes fields (key=value) where the value is empty if it is the last value with the same key.
	 * Example: "CN=abc,CN=,CN=def,O=,O=abc,O=" will become "CN=abc,CN=,CN=def,O=,O=abc".
	 * @param sDN the String to clean.
	 * @return a copy of the String where the value is empty if it is the last value with the same key.
	 */
    public static String removeTrailingEmpties(final String sDN) {
    	final StringBuilder sb = new StringBuilder(sDN);
    	int lastPairWithNonEmptyValue = sb.length();
    	for (int i=sb.length()-1; i>=0; i--) {
    		if (sb.charAt(i) == ',' && isNotEscaped(sb, i)) {	// Not escaped ','
    			final int startOfThisPair = getStartPos(sb, i-1);
    			if (sb.charAt(i-1) == '=') {	// '='
    				// If last char was '=' this value was empty and should be removed UNLESS FOLLOWED BY A PAIR WITH THE SAME KEY AND NON-EMPTY VALUE
    				if (!hasSameKey(sb, startOfThisPair, lastPairWithNonEmptyValue)) {
    					// Delete this pair, since it is the last one with this key
    					sb.delete(startOfThisPair, lastPairWithNonEmptyValue);
    					// Since the next pair has a different key we know the "startOfThisPair" is the new position
    					lastPairWithNonEmptyValue = startOfThisPair;
    				}
    			} else {
    				lastPairWithNonEmptyValue = startOfThisPair;
    			}
    		}
    	}
    	return sb.toString();
    }

    /** @return true if an even number of '\' precedes this position in the buffer. */
    private static boolean isNotEscaped(final StringBuilder sb, final int pos) {
    	boolean evenEscapes = true;
    	for (int i=pos-1; i>=0; i--) {
    		if (sb.charAt(i) == '\\') {
    			evenEscapes ^= true;
    		} else {
    			break;
    		}
    	}
    	return evenEscapes;
    }

    /** Find the position of the closest not escaped ',' before this position in the buffer. */
    private static int getStartPos(final StringBuilder sb, final int pos) {
    	for (int i=(pos>=sb.length()?sb.length()-1:pos); i>=0; i--) {
    		if (sb.charAt(i) == ',' && isNotEscaped(sb, i)) {	// Not escaped ','
    			return i+1;
    		}
    	}
    	return 0;
    }
    
    /** Compares the two character sequences in the buffer at the positions until a not escaped '=' is found. */
    private static boolean hasSameKey(final StringBuilder sb, final int pos1, final int pos2) {
    	final int len = sb.length();
    	int i = 0;
    	boolean iOnlySpace = true;
    	int j = 0;
    	boolean jOnlySpace = true;
    	while (len>pos1+i && len>pos2+j ) {
        	final char c1 = sb.charAt(pos1+i);
        	if (iOnlySpace && c1 == ' ') {
        		// Skip spaces in the beginning
        		i++;
        		continue;
        	} else {
        		iOnlySpace = false;
        	}
        	final char c2 = sb.charAt(pos1+j);
        	if (jOnlySpace && c2 == ' ') {
        		// Skip spaces in the beginning
        		j++;
        		continue;
        	} else {
        		jOnlySpace = false;
        	}
        	if (c1 != c2) {
        		return false;
        	}
        	if (c1 == '=' && isNotEscaped(sb, pos1+i)) {	// Not escaped '='
        		return true;
        	}
        	i++;
        	j++;
    	}
    	return false;
    }
}
