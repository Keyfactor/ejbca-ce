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

package org.cesecore.certificates.ocsp.logging;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.bouncycastle.util.encoders.Hex;

/**
 * This class can be extended to create highly configurable log classes. Values that are to be logged are stored in a Hashmap and the output is
 * configured using a Java.util.regex.Matcher and a sortString. The extending classes also need to supply a Logger and a String specifying how to log
 * Dates.
 * 
 * Use paramPut(String key, String value) to add values, Use writeln() to log all the stored values and then use flush() to store them to file.
 * 
 * Roughly based on PatternLogger.java 8663 2010-02-17 10:42:41Z anatom from EJBCA
 * 
 * @version $Id$
 */
public abstract class PatternLogger {

    public static final String LOG_TIME = "LOG_TIME";// The Date and time the request.
    public static final String LOG_ID = "LOG_ID"; // An integer identifying a log entry for a request
    public static final String SESSION_ID = "SESSION_ID"; // A random 32 bit number identifying a log entry for a request

    public static final String REPLY_TIME = "REPLY_TIME";

    /**
     * Hash of the issuer DN
     */
    public static final String ISSUER_NAME_HASH = "ISSUER_NAME_HASH";
    /**
     * The public key of the issuer of a requested certificate
     */
    public static final String ISSUER_KEY = "ISSUER_KEY";
    /**
     * Serial number of the requested certificate.
     */
    public static final String SERIAL_NOHEX = "SERIAL_NOHEX";
    /**
     * IP of the client making the request
     */
    public static final String CLIENT_IP = "CLIENT_IP";
    /**
     * The status of the OCSP-Request. SUCCESSFUL = 0;MALFORMED_REQUEST = 1;INTERNAL_ERROR = 2;
     */
    public static final String STATUS = "STATUS";

    /**
     * PROCESS_TIME is a marker that is used to record the total time a request takes to process, excluding reading the request. It is replaced with
     * the correct value when the log entry is written. the time measurement start when this param is set in the logger with:
     * 
     * <pre>
     * ocspTransactionLogger(PROCESS_TIME, PROCESS_TIME);
     * </pre>
     * 
     * This means that this variable can be used to measure any time you want to measure in your code.
     * 
     */
    public static final String PROCESS_TIME = "PROCESS_TIME";

    private final Map<String, String> valuepairs = new HashMap<String, String>();
    private final StringWriter sw = new StringWriter();
    private final PrintWriter pw = new PrintWriter(this.sw);
    private final Matcher m;
    private final String orderString;
    private final String logDateFormat;
    private final String timeZone;
    private final Date startTime;
    private Date startProcessTime = null;
    private boolean doLogging;

    /**
     * @param doLogging
     *            True if you want this pattern logger to do anything upon flush.
     * @param matchPattern
     *            A string to create a matcher that is used together with matchString to determine how output is formatted
     * @param matchString
     *            A string that matches the pattern in m and specifies the order in which values are logged by the logger
     * @param logger
     *            A log4j Logger that is used for output
     * @param logDateFormat
     *            A string that specifies how the log-time is formatted
     * @param timeZone
     */
    protected PatternLogger(boolean doLogging, String matchPattern, String matchString, String logDateFormat, String timeZone) {
        this.doLogging = doLogging;
        this.m = Pattern.compile(matchPattern).matcher(matchString);
        this.orderString = matchString;
        this.logDateFormat = logDateFormat;
        this.timeZone = timeZone;
        this.startTime = new Date();
        final FastDateFormat dateformat;
        if (this.timeZone == null) {
                dateformat = FastDateFormat.getInstance(this.logDateFormat);
        } else {
                dateformat = FastDateFormat.getInstance(this.logDateFormat, TimeZone.getTimeZone(this.timeZone));
        }
        paramPut(LOG_TIME, dateformat.format(new Date()));
        this.paramPut(REPLY_TIME, REPLY_TIME);
        this.paramPut(LOG_ID, "0");
    }

    /**
     * 
     * @return output to be logged
     */
    private String interpolate() {
        final StringBuffer sb = new StringBuffer(this.orderString.length());
        this.m.reset();
        while (this.m.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            final String key = this.m.group(1);
            final String value = this.valuepairs.get(key);

            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                this.m.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                this.m.appendReplacement(sb, "");
                final String unknown = this.m.group(0);
                sb.append(unknown);
            }
        }
        this.m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Hex-encodes the bytes.
     * method that makes sure that a "" is inserted instead of null
     * @param key
     * @param value
     */
    public void paramPut(String key, byte[] value) {
        paramPut(key, new String(Hex.encode(value)));
    }

    /**
     * method that makes sure that a "" is inserted instead of null
     * @param key
     * @param value
     */
    public void paramPut(String key, String value) {
        // logger.debug("paramput: "+ key+ ";" +value +";" +valuepairs.toString());
        if (value == null) {
            this.valuepairs.put(key, "");
        } else {
            this.valuepairs.put(key, value);
        }
        if (StringUtils.equals(key, PROCESS_TIME)) {
            startProcessTime = new Date();
        }
    }

    /**
     * method that makes sure that a "" is inserted instead of null
     * @param key
     * @param value
     */
    public void paramPut(String key, Integer value) {
        if (value == null) {
            this.valuepairs.put(key, "");
        } else {
            this.valuepairs.put(key, value.toString());
        }
    }

    /**
     * Method used for creating a log row of all added values
     */
    public void writeln() {
        if (doLogging) {
            this.pw.println(interpolate());
        }
    }

    /**
     * Writes all the rows created by writeln() to the Logger
     */
    public void flush() {
        if (doLogging) {
            this.pw.flush();
            String output = this.sw.toString();
            output = output.replaceAll(REPLY_TIME, String.valueOf(new Date().getTime() - this.startTime.getTime()));
            if (startProcessTime != null) {
                output = output.replaceAll(PROCESS_TIME, String.valueOf(new Date().getTime() - this.startProcessTime.getTime()));
            }
        }
    }
}
