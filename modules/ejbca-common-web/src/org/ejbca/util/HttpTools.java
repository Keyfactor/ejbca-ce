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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.Part;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.StringTools;

/**
 * Utility methods for working with HTTP related things (file uploads, headers etc.)
 * 
 * @version $Id$
 */
public class HttpTools {

    private static final Logger log = Logger.getLogger(HttpTools.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTHORIZATION_SCHEME_BEARER = "Bearer";

    // For parsing parameters in the Content-Disposititon header (or possibly other headers) according to RFC 6266
    private static final String PARAM_NAME_REGEX = "[a-zA-Z0-9_+*-]++";
    private static final String PARAM_VALUE_REGEX = "\"(([^\\\\\"]|\\\\.)*)\"|([^\\s;\"]*+)";
    private static final Pattern headerParameter = Pattern.compile(";\\s*+(" + PARAM_NAME_REGEX + ")\\s*+=\\s*+(" + PARAM_VALUE_REGEX + ")\\s*+");
    // These correspond to different parentheses in the regex above.
    private static final int PARAM_NAME_GROUP = 1;
    private static final int PARAM_QUOTED_VALUE_GROUP = 3;
    private static final int PARAM_UNQUOTED_VALUE_GROUP = 5;
    
    /** Utility class. Cannot be instantiated */
    private HttpTools() {}

    /**
     * Extracts the filename from an Content-Disposition HTTP header, according to RFC 6266.
     * <p>
     * The result will not be backslash-unescaped, since some browsers do not escape the values.
     *
     * @param headerValue Header value. May be null.
     * @param parameterName Parameter to extract.
     * @return Extracted filename, without quotes or file path, or empty string if there's an error.
     */
    public static String extractParameterFromHeader(final String headerValue, final String parameterName) {
        if (headerValue == null) {
            return "";
        }
        // The syntax is:
        // type; parameter1=value1; parameter2="value2\"example"; parameter3="some value3"
        final int paramsStart = headerValue.indexOf(';');
        if (paramsStart == -1) {
            return "";
        }
        final String params = headerValue.substring(paramsStart);
        final Matcher nameMatcher = headerParameter.matcher(params);
        while (nameMatcher.find()) {
            final String paramName = nameMatcher.group(PARAM_NAME_GROUP);
            if (StringUtils.equalsIgnoreCase(paramName, parameterName)) {
                final String quoted = nameMatcher.group(PARAM_QUOTED_VALUE_GROUP);
                final String unquoted = nameMatcher.group(PARAM_UNQUOTED_VALUE_GROUP);
                final String paramValue = quoted != null ? quoted : unquoted;
                if (log.isTraceEnabled()) {
                    log.trace("Matched header parameter for string '" + headerValue +
                            "' --> " + paramName + "/" + nameMatcher.group(2) + // full value, with quotes
                            " --> " + quoted + "/" + unquoted);
                }
                return StringUtils.defaultString(paramValue);
            }
        }
        return "";
    }

    /**
     * Extracts the filename from a file upload.
     * @param servletHttpPart Part object from <h:inputFile> value. May <b>not</b> be null.
     * @return Filename, without file path, or empty string if there's an error.
     */
    public static String getUploadFilename(final Part servletHttpPart) {
        final String contentDisposition = servletHttpPart.getHeader("Content-Disposition");
        if (log.isDebugEnabled()) {
            log.debug("Content-Disposition header from upload: " + StringTools.stripLog(contentDisposition));
        }
        return getUploadFilenameFromHeader(contentDisposition);
    }

    /**
     * Extracts the filename from an Content-Disposition HTTP header, according to RFC 6266.
     *
     * @param contentDisposition Header value. May be null.
     * @return Extracted filename, without quotes or file path, or empty string if there's an error.
     */
    public static String getUploadFilenameFromHeader(final String contentDisposition) {
        // First try to parse the "filename*" parameter (new syntax from RFC 5987)
        final String filenameExt = extractParameterFromHeader(contentDisposition, "filename*");
        String filename = decodeRfc5987(filenameExt);
        // Then try to decode as old style "filename" parameter
        if (filename == null) {
            final String filenameOld = extractParameterFromHeader(contentDisposition, "filename");
            filename = urlDecode(filenameOld);
        }
        filename = StringUtils.defaultString(filename); // empty string instead of null
        return FilenameUtils.getName(filename);
    }

    /**
     * Decodes a RFC 5987 parameter.
     * @return Decoded string or null on error.
     */
    public static String decodeRfc5987(final String encoded) {
        if (StringUtils.isEmpty(encoded)) {
            return null;
        }
        final String[] pieces = encoded.split("'", 3); // format is:  charset'language'data
        if (pieces.length != 3) {
            log.debug("Too few ' characters in RFC 5987 encoded HTTP header parameter.");
            return null;
        }
        final String charset = pieces[0];
        final String data = pieces[2];
        try {
            return URLDecoder.decode(data, charset);
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Got unsupported character encoding '" + StringTools.stripLog(charset) + "' in RFC 5987 encoded header parameter.");
            }
            return null;
        }
    }

    /**
     * Decodes URL encoded data. Tries to decode as UTF-8, with ISO-8859-1 (Latin1) as a fallback.
     * If decoding fails, then it returns the string unmodified.
     */
    public static String urlDecode(final String s) {
        try {
            final String decoded = URLDecoder.decode(s, "UTF-8");
            if (decoded.contains("\uFFFD")) { // replacement character for invalid characters
                return URLDecoder.decode(s, "ISO-8859-1");
            }
            return decoded;
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return s;
        }
    }

    /**
     * Checks if the given Authorization header value matches the given scheme, and returns the contents (except for the scheme name).
     *
     * @param authorizationHeader Value of the Authorization header, may be null.
     * @param expectedScheme Scheme to check for.
     * @return Header value without scheme part, or null if not matching the scheme.
     */
    public static String extractAuthorizationOfScheme(final String authorizationHeader, final String expectedScheme) {
        if (StringUtils.startsWithIgnoreCase(authorizationHeader, expectedScheme+" ")) {
            return authorizationHeader.split(" +", 2)[1];
        } else {
            return null;
        }
    }

    /** Extracts the Bearer authorization from an OAuth Authorization header, or returns null if not matching */
    public static String extractBearerAuthorization(final String authorizationHeader) {
        return extractAuthorizationOfScheme(authorizationHeader, AUTHORIZATION_SCHEME_BEARER);
    }

}
