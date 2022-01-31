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
package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.util.Map;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.config.Configuration;

import org.junit.rules.ExternalResource;

// TODO ECA-8963: Extract into a separate module ejbca-unittest, as it is common utility class that can be reused.
/**
 * This is a help class, implementing a @Rule to catch log4j logging messages.
 *
 * @version $Id$
 */
public class TestLogAppenderResource extends ExternalResource {

    private static final String APPENDER_NAME = "log4jRuleAppender";

    private LoggerContext context;
    private WriterAppender appender;
    final StringWriter writer = new StringWriter();

    public TestLogAppenderResource(final Logger logger) {
        this.context = ((org.apache.logging.log4j.core.Logger) logger).getContext();
    }

    @Override
    protected void before() {
        final Configuration config = context.getConfiguration();
        final Map.Entry<String, Appender> existing = config.getAppenders().entrySet().iterator().next();
        appender = WriterAppender.newBuilder().setConfiguration(config).setName(APPENDER_NAME).setLayout(existing.getValue().getLayout()).setTarget(writer).build();
        appender.start();
        context.getRootLogger().addAppender(appender);
    }

    @Override
    protected void after() {
        appender.stop();
        context.getRootLogger().removeAppender(appender);

    }

    public String getOutput() {
        return writer.toString();
    }

}
