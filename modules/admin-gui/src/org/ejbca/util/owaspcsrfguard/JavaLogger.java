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
package org.ejbca.util.owaspcsrfguard;

import org.apache.log4j.Logger;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;

/** A logging class for the OWASP CSRF Guard filter.
 * https://www.owasp.org/index.php/Csrfguard
 * We need a custom logger because it is not possible to configure CSRFguard at what level it shold log, so we filter on our own here.
 * 
 * @version $Id$
 */
public class JavaLogger implements ILogger {

    private static final long serialVersionUID = -4857601483759096197L;

    private final static Logger log = Logger.getLogger(JavaLogger.class);

    @Override
    public void log(String msg) {
        if (log.isTraceEnabled()) {
            log.trace(msg.replaceAll("(\\r|\\n)", ""));
        }
    }

    @Override
    public void log(LogLevel level, String msg) {
        // Remove CR and LF characters to prevent CRLF injection
        String sanitizedMsg = msg.replaceAll("(\\r|\\n)", "");

        // We don't want to spam the EJBCA log with OWASP stuff, so we'll log everything that are not warning or error at Trace level
        switch (level) {
        case Trace:
            if (log.isTraceEnabled()) {
                log.trace(sanitizedMsg);
            }
            break;
        case Debug:
            if (log.isTraceEnabled()) {
                log.trace(sanitizedMsg);
            }
            break;
        case Info:
            if (log.isTraceEnabled()) {
                log.trace(sanitizedMsg);
            }
            break;
        case Warning:
            log.warn(sanitizedMsg);
            break;
        case Error:
            log.warn(sanitizedMsg);
            break;
        case Fatal:
            log.error(sanitizedMsg);
            break;
        default:
            throw new RuntimeException("unsupported log level " + level);
        }
    }

    @Override
    public void log(Exception exception) {
        log.warn(exception.getLocalizedMessage(), exception);
    }

    @Override
    public void log(LogLevel level, Exception exception) {
        // We don't want to spam the EJBCA log with OWASP stuff, so we'll log everything that are not warning or error at Trace level
        switch(level) {
        case Trace:
            if (log.isTraceEnabled()) {
                log.trace(exception.getLocalizedMessage(), exception);
            }
            break;
        case Debug:
            if (log.isTraceEnabled()) {
                log.trace(exception.getLocalizedMessage(), exception);
            }
            break;
        case Info:
            if (log.isTraceEnabled()) {
                log.trace(exception.getLocalizedMessage(), exception);
            }
            break;
        case Warning:
            log.warn(exception.getLocalizedMessage(), exception);
            break;
        case Error:
            log.warn(exception.getLocalizedMessage(), exception);
            break;
        case Fatal:
            log.error(exception.getLocalizedMessage(), exception);
            break;
        default:
            throw new IllegalArgumentException("unsupported log level " + level);
        }
    }
}