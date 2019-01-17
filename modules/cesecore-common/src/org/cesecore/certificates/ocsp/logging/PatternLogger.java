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
import java.io.Serializable;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
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
public abstract class PatternLogger implements Serializable {

    private static final long serialVersionUID = 8486004615125959046L;
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
    private final String matchString;
    private final String matchPattern;
    // Matcher is not Serializable
    private transient Matcher m;
    private final String orderString;
    private final Date startTime;
    private Date startProcessTime = null;
    private boolean doLogging;
    final private Class<?> loggerClass;
    // Logger is not Serializable
    private transient Logger logger;

    // for writing the output
    private transient StringWriter sw;
    private transient PrintWriter pw;

    /**
     * @param doLogging
     *            True if you want this pattern logger to do anything upon flush.
     * @param logger
     *            The Class to create Log4j logger for, to log to if doLogging is true
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
    protected PatternLogger(boolean doLogging, Class<?> loggerClass, String matchPattern, String matchString, String logDateFormat, String timeZone) {
        this.doLogging = doLogging;
        this.matchString = matchString;
        this.matchPattern = matchPattern;
        this.orderString = matchString;
        this.loggerClass = loggerClass;
        this.startTime = new Date();
        final FastDateFormat dateformat;
        if (timeZone == null) {
                dateformat = FastDateFormat.getInstance(logDateFormat);
        } else {
                dateformat = FastDateFormat.getInstance(logDateFormat, TimeZone.getTimeZone(timeZone));
        }
        paramPut(LOG_TIME, dateformat.format(new Date()));
        this.paramPut(REPLY_TIME, REPLY_TIME);
        this.paramPut(LOG_ID, "0");
    }
    
    private Matcher getMatcher() {
        if (this.m == null) {
            // We have to instantiate the Matcher in the class and can not have it as an instance variable.
            // This is because we are sending this object to a remote EJB (at least in system tests)
            this.m = Pattern.compile(matchPattern).matcher(matchString);
        }
        return this.m;
    }

    private Logger getLogger() {
        if (this.logger == null) {
            // We have to instantiate the logger in the class and can not have it as an instance variable.
            // This is because we are sending this object to a remote EJB (at least in system tests) and org.apache.log4j.Logger is not serializable.
            this.logger = Logger.getLogger(loggerClass);
        }
        return this.logger;
    }

    private PrintWriter getPrintWriter() {
        if (this.pw == null) {
            this.sw = new StringWriter();
            this.pw = new PrintWriter(this.sw);
        }
        return pw;
    }
    
    /**
     * 
     * @return output to be logged
     */
    private String interpolate() {
        final StringBuffer sb = new StringBuffer(this.orderString.length());
        final Matcher matcher = getMatcher();
        matcher.reset();
        while (matcher.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            final String key = matcher.group(1);
            final String value = this.valuepairs.get(key);

            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                matcher.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                matcher.appendReplacement(sb, "");
                final String unknown = matcher.group(0);
                sb.append(unknown);
            }
        }
        matcher.appendTail(sb);
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
            getPrintWriter().println(interpolate());
        }
    }

    /**
     * Writes all the rows created by writeln() to the Logger
     */
    public void flush() {
        if (doLogging) {
            getPrintWriter().flush();
            String output = this.sw.toString();
            output = output.replaceAll(REPLY_TIME, String.valueOf(new Date().getTime() - this.startTime.getTime()));
            if (startProcessTime != null) {
                output = output.replaceAll(PROCESS_TIME, String.valueOf(new Date().getTime() - this.startProcessTime.getTime()));
            }
            //Remove an extra linebreak between flushes.
            if(output.endsWith(System.getProperty("line.separator"))) {
                output = output.substring(0, output.length()-1);
            }
            getLogger().debug(output); // Finally output the log row to the logging device
        }
    }

    /** @return true if this logger is enabled */
    public boolean isEnabled() {
        return doLogging && getLogger().isDebugEnabled();
    }
}
