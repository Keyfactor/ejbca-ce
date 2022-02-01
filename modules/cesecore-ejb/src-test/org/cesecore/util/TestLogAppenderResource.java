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
package org.cesecore.util;

import java.io.ByteArrayOutputStream;

import org.apache.log4j.Appender;
import org.apache.log4j.Layout;
import org.apache.log4j.Logger;
import org.apache.log4j.SimpleLayout;
import org.apache.log4j.WriterAppender;
import org.junit.rules.ExternalResource;

// TODO ECA-8963: Extract into a separate module ejbca-unittest, as it is common utility class that can be reused.
/**
 * This is a help class, implementing a @Rule to catch log4j logging messages.
 *
 * @version $Id$
 */
public class TestLogAppenderResource extends ExternalResource {

    private static final String APPENDER_NAME = "log4jRuleAppender";
    private static final Layout LAYOUT = new SimpleLayout();

    private final Logger logger;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();

    public TestLogAppenderResource(final Logger logger) {
        this.logger = logger;
    }

    @Override
    protected void before() {
        Appender appender = new WriterAppender(LAYOUT, outContent);
        appender.setName(APPENDER_NAME);
        logger.addAppender(appender);
    }

    @Override
    protected void after() {
        logger.removeAppender(APPENDER_NAME);
    }

    public String getOutput() {
        return outContent.toString();
    }

}
