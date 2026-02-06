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

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

public class UrlQueryParamsValidator {

    private UrlQueryParamsValidator() {}

    // RFC 3986 + security hardening
    // Control chars + dangerous symbols
    private static final Pattern FORBIDDEN_CHARS =
            Pattern.compile("[\\p{Cntrl}\"\'<>\\\\^`{}|]");

    // Strict percent-encoding validation
    private static final Pattern VALID_PERCENT_ENCODING =
            Pattern.compile("(%[0-9A-Fa-f]{2}|[^%])*");
    
    public static final Set<String> INTEGER_QUERY_PARAMS = Set.of("maxNumberOfResults", "offset", "crlPartitionIndex");
    
    public static final Set<String> BOOLEAN_QUERY_PARAMS = Set.of("includeExternal", "deltaCrl", "deltacrl"); //yup


    /**
     * Validates a query string from a EJBCA REST API URL. 
     * It should not be used for validating UI or other URL e.g. SCEP, OCSP etc
     *
     * @param queryString e.g. "q=rock%26roll&page=1&enabled=false"
     * @return true if the query is safe, else false
     */
    public static boolean validateRestApiUrlQueryParams(String queryString) {
        
        if(StringUtils.isBlank(queryString)) {
            return true;
        }
        
        // url may end with #
        if (queryString.endsWith("#")) {
            queryString = queryString.substring(0, queryString.length()-1);
        }
        String[] pairs = queryString.split("&");

        for (String pair : pairs) {
            String key;
            String value;

            int idx = pair.indexOf('=');
            if (idx < 0) {
                key = pair;
                // allow empty values, even in middle as there are further validations
                value = "";
            } else {
                key = pair.substring(0, idx);
                value = pair.substring(idx + 1);
            }
            
            if (INTEGER_QUERY_PARAMS.contains(key)) {
                try {
                    Integer.parseInt(value);
                    continue;
                } catch(NumberFormatException e) {
                    return false;
                }
            }
            
            if (BOOLEAN_QUERY_PARAMS.contains(key)) {
                if (!value.equals("true") && !value.equals("false") ) {
                    return false;
                }
                continue;
            }

            if (!validateComponent(key, false) || !validateComponent(value, true)) {
              return false; // unsafe query detected
          }
        }
        
        return true;
    }

    private static boolean validateComponent(String raw, boolean isValue) {
        
        // allow empty value but reject empty keys
        if (StringUtils.isBlank(raw)) {
            return isValue;
        }
        
        // deny malformed percent encoding
        if (!VALID_PERCENT_ENCODING.matcher(raw).matches()) {
            return false;
        }

        String decoded = URLDecoder.decode(raw, StandardCharsets.UTF_8);
        // deny double encoding
        String reEncoded = URLEncoder.encode(decoded, StandardCharsets.UTF_8);
        // special handling for asterisk
        raw = raw.replace("%2A", "*");
        String reEncodedPercentEscaped = reEncoded.replace("%3A", ":");
        if (!reEncoded.equals(raw) && !reEncodedPercentEscaped.equals(raw)) {
            return false;
        }

        // detect forbidden characters with and without decoding
        if (FORBIDDEN_CHARS.matcher(decoded).find() || FORBIDDEN_CHARS.matcher(raw).find()) {
            return false;
        }
        
        int indexOfHash = raw.indexOf('#');
        // only allow hash in last character
        // deny if last key contains hash and no value
        if (indexOfHash!=-1 && indexOfHash!=raw.length()-1 && !isValue) {
            return false;
        }
        
        return true;
    }
}