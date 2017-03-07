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
package org.cesecore.certificates.util.dn;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * DN string utilities.
 * 
 * Optimized to lower object instantiation by performing manipulations "in-place" using StringBuilder and char[].
 * 
 * Not built to handle '+' char separators or take special consideration to Unicode.
 * Current implementation will treat unescaped '=' in values as ok (backwards compatible).
 * 
 * @version $Id$
 */
public abstract class DNFieldsUtil {

	private static final Logger LOG = Logger.getLogger(DNFieldsUtil.class);
	private static final int EMPTY = -1;
	private static final String MSG_ERROR_MISSING_EQUAL = "DN field definition is missing the '=': ";
	private static final String ATTRIBUTE_SEPARATOR = ",";
	private static final String KEY_VALUE_SEPARATOR = "=";
	
	/**
     * The method splits an DN string into a map of it's attributes and values.
     * 
     * @param dnString the DN String to split (i.e.: 'C=DE,CN=test,SN=1').
     * @return a map containing the attributes and values.
     */
    public static final Map<String, String> dnStringToMap(final String dnString) {
        final String[] dnTokens = dnString.split(ATTRIBUTE_SEPARATOR);
        final Map<String, String> result = new HashMap<String,String>();
        if (StringUtils.isNotBlank(dnString)) {
            String[] tokens;
            for (int i = 0; i<dnTokens.length;i++) {
                tokens = dnTokens[i].split(KEY_VALUE_SEPARATOR);
                if (tokens.length > 1) {
                    result.put(tokens[0], tokens[1]);
                } else {
                    result.put(tokens[0], StringUtils.EMPTY);
                }
            }
        }
        return result;
    }
    
    /**
     * The method checks if the subject-DN contains both C and CN attributes
     * (in a potential CVCA/CSCA certificate at least the attributes C and CN must be set).
     * 
     * @param map the map of DN attributes and values.
     * @return true if the DN map contains non-empty values for both C and CN.
     */
    private static final boolean mapContainsCountryAndCN(final Map<String,String> map) {
        boolean result = false;
        if (map.size() >= 2) {
            result = StringUtils.isNotBlank(map.get("C")) && StringUtils.isNotBlank(map.get("CN"));
        }
        return result;
    }

    /**
     * The method checks if the two subject-DN belongs to the same CSCA (C and CN must be equal, SN could be changed).
     * @param map1 the left side subject-DN map.
     * @param map2 the right side subject-DN map.
     * @return true if both subject-DN belongs to the same CSCA.
     */
    public static final boolean caCertificatesOfSameCSCA(final Map<String,String> map1, final Map<String,String> map2) {
        if (!mapContainsCountryAndCN(map1) || !mapContainsCountryAndCN(map2)) {
            return false;
        }
        return StringUtils.equals(map1.get("C"), map2.get("C")) && StringUtils.equals(map1.get("CN"), map2.get("CN"));
    }


	/** Invoke removeEmpties and only return the fully clean dn String. */
	public static String removeAllEmpties(final String dn) {
		if (dn==null) {
			return null;
		}
    	final StringBuilder removedAllEmpties = new StringBuilder(dn.length());
    	DNFieldsUtil.removeEmpties(dn, removedAllEmpties, false);
		return removedAllEmpties.toString();
	}

	/**
	 * This method will take the supplied string and fill the two provided empty StringBuilders.
	 * 
	 * removedTrailingEmpties is produced by:
	 * Removes fields (key=value) where the value is empty if it is the last value with the same key.
	 * Example: "CN=abc,CN=,CN=def,O=,O=abc,O=" will become "CN=abc,CN=,CN=def,O=,O=abc".
	 * Example: "CN=abc,DC=,O=,CN=def,O=,O=abc,O=" will become "CN=abc,O=,CN=def,O=,O=abc".
	 * 
	 * removedAllEmpties is produced by:
	 * Removes all fields (key=value) where the value is empty.
	 * Example: "CN=abc,CN=,O=,CN=def,O=,O=abc,O=" will become "CN=abc,CN=def,O=abc".
	 * 
	 * Since the algorithms are very similar for these two it makes sense to calculate them both at
	 * the same time for use in EndEntityInformation.
	 * 
	 * @param sDN the String to clean.
	 * @param processTrailing true is removedTrailingEmpties should be considered.
	 * @return removedTrailingEmpties StringBuilder if both types of cleaning give different results or null if they are the same.
	 */
	public static StringBuilder removeEmpties(final String sDN, final StringBuilder removedAllEmpties, final boolean processTrailing) {
		StringBuilder removedTrailingEmpties = null;
    	// First make a list of where all the key=value pairs start and if they are empty or not
    	final List<Integer> startOfPairs = new ArrayList<Integer>();
    	final List<Integer> startOfValues = new ArrayList<Integer>();
    	final char[] buf = sDN.toCharArray();
    	populatePositionLists(startOfPairs, startOfValues, buf);
    	boolean areStringBuildersEqual = true;
    	// Go through all the pairs from first to last
    	for (int i=0; i<startOfPairs.size(); i++) {
    		final int startOfThisPair = startOfPairs.get(i).intValue();
    		final int startOfNextPair;
    		if (i == startOfPairs.size()-1) {
    			startOfNextPair = buf.length;	// The "next element" begins at the end of the buffer
    		} else {
    			startOfNextPair = startOfPairs.get(i+1).intValue();
    		}
    		final int startOfThisValue = startOfValues.get(i).intValue();
    		boolean addOnlyNonTrailingEmpties = true;
    		boolean addAllNonEmpties = true;
    		if (startOfThisValue == EMPTY) {
    	    	// If a pair is empty
    			addOnlyNonTrailingEmpties = false;
    			addAllNonEmpties = false;
    			// If we only remove trailing empties there is a second chance that we will still add it..
    			if (processTrailing) {
        			for (int j=i+1; j<startOfPairs.size(); j++) {
        				final int startOfThisPair2 = startOfPairs.get(j).intValue();
        				if (hasSameKey(buf, startOfThisPair, startOfThisPair2) && startOfValues.get(j).intValue() != EMPTY) {
        					// if this was not the last pair with this key and one of the later ones is not empty: add it!
        					addOnlyNonTrailingEmpties = true;
        					break;
        				}
        			}
    			}
    		}
    		if (areStringBuildersEqual && (addOnlyNonTrailingEmpties != addAllNonEmpties)) {
    			// The StringBuilders are no longer equal, so we need to populate the empty one and let them diverge
    			areStringBuildersEqual = false;
    			if (processTrailing) {
        			removedTrailingEmpties = new StringBuilder(removedAllEmpties);
    			}
    		}
    		if (addAllNonEmpties) {
    			removedAllEmpties.append(buf, startOfThisPair, startOfNextPair-startOfThisPair);
    		}
    		if (processTrailing && !areStringBuildersEqual && addOnlyNonTrailingEmpties) {
    			removedTrailingEmpties.append(buf, startOfThisPair, startOfNextPair-startOfThisPair);
    		}
    	}
    	removeUnwatedLastChars(removedAllEmpties);
    	if (!areStringBuildersEqual) {
        	removeUnwatedLastChars(removedTrailingEmpties);
    	}
    	return removedTrailingEmpties;
    }
	
	/** 
	 * If we end up with a buffer ending with "," or ", " we need to remove these chars unless they've been escaped with a '\'
	 * 
	 * @param sb A StringBuilder to work in. 
	 */
    private static void removeUnwatedLastChars(final StringBuilder sb) {
        if (sb.length() > 0) {
            for (int i = sb.length() - 1; i >= 0; i--) {
                final char c = sb.charAt(i);
                if (c == ' ' || c == ',') {
                    if (sb.charAt(i - 1) == '\\') {
                        break;
                    } else {
                        sb.deleteCharAt(i);
                    }
                } else {
                    break;
                }
            }
        }
    }

	/** Populates the two lists with starting positions in the character buffer where the value=key pair begins and keys begin. */
    private static void populatePositionLists(final List<Integer> startOfPairs, final List<Integer> startOfValues, final char[] buf) {
    	if (buf.length>0) {
        	startOfPairs.add(Integer.valueOf(0));
    	}
    	boolean notEscaped = true;	// Keep track of what is escapes and not
    	for (int i=0; i<buf.length; i++) {
    		switch (buf[i]) {
    		case '\\':
    			notEscaped ^= true;
    			break;
    		case ',':
    			if (notEscaped) {
        			if (startOfPairs.size() > startOfValues.size()) {
        				// We are missing a '=' in the DN!
        				LOG.info(MSG_ERROR_MISSING_EQUAL + new String(buf));
        			}
    				int j = i+1;
    				while (j<buf.length && buf[j] == ' ') {
    					j++;	// Ignore spaces
    				}
    				startOfPairs.add(Integer.valueOf(j));
    			} else {
    				notEscaped = true;
    			}
    			break;
    		case '=':
    			if (notEscaped) {
    				// Only use the first '=' after a ',' (backwards compatible)
        			if (startOfPairs.size() > startOfValues.size()) {
        				int j = i+1;
        				while (j<buf.length && buf[j] == ' ') {
        					j++;	// Ignore spaces
        				}
        				if (j>=buf.length || buf[j] == ',') {
        					startOfValues.add(Integer.valueOf(EMPTY));	// Use -1 to mark that the value is empty
        				} else {
        					startOfValues.add(Integer.valueOf(j));
        				}
        			}
    			} else {
    				notEscaped = true;
    			}
    			break;
    		default:
    			notEscaped=true;
    		}
    	}
    }

    /** Compares the two character sequences in the buffer at the positions until a not escaped '=' is found. */
    private static boolean hasSameKey(final char[] sb, int pos1, int pos2) {
    	final int len = sb.length;
    	boolean notEscaped = true;	// Keep track of what is escapes and not
    	while (len>pos1 && len>pos2 ) {
        	final char c1 = sb[pos1];
        	switch (c1) {
        	case '\\':
    			notEscaped ^= true;
    			break;
        	case '=':
        		if (notEscaped && c1 == sb[pos2]) {
        			return true;
        		} // else.. continue with the default action..
        	default:
            	if (c1 != sb[pos2]) {
            		return false;
            	}
    			notEscaped=true;
        	}
        	pos1++;
        	pos2++;
    	}
    	return false;
    }
}
