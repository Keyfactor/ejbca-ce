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
package org.ejbca.core.ejb.upgrade;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;

import org.apache.log4j.Appender;
import org.apache.log4j.Layout;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.Filter;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Singleton responsible for keep track of a node-local post upgrade.
 * 
 * @version $Id$
 */
@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
@TransactionManagement(TransactionManagementType.BEAN)
public class UpgradeStatusSingletonBean implements UpgradeStatusSingletonLocal {

    /** Custom appender so that we can capture and display the log from the upgrade process. */
    private final Appender appender = new Appender() {
        @Override
        public void addFilter(Filter filter) {}
        @Override
        public void clearFilters() {}
        @Override
        public void close() {}
        @Override
        public ErrorHandler getErrorHandler() { return null; }
        @Override
        public Filter getFilter() { return null; }
        @Override
        public Layout getLayout() { return null; }
        @Override
        public boolean requiresLayout() { return false; }
        @Override
        public void setErrorHandler(final ErrorHandler errorHandler) {}
        @Override
        public void setLayout(final Layout layout) {}
        @Override
        public void setName(final String name) {}

        @Override
        public String getName() {
            return UpgradeStatusSingletonBean.class.getSimpleName();
        }

        @Override
        public void doAppend(final LoggingEvent loggingEvent) {
            logged.add(loggingEvent);
        }
    };

    private AtomicBoolean postUpgradeInProgress = new AtomicBoolean(false);
    private List<LoggingEvent> logged = new ArrayList<>();
    
    @Override
    public boolean isPostUpgradeInProgress() {
        return postUpgradeInProgress.get();
    }

    @Override
    public boolean setPostUpgradeInProgressIfDifferent(boolean newValue) {
        logged.clear();
        return this.postUpgradeInProgress.compareAndSet(!newValue, newValue);
    }
    
    @Override
    public void resetPostUpgradeInProgress() {
        this.postUpgradeInProgress.set(false);
    }
    
    @Override
    public List<LoggingEvent> getLogged() {
        return logged;
    }
    
    @Override
    public void logAppenderAttach(final Logger log) {
        log.addAppender(appender);
    }

    @Override
    public void logAppenderDetach(final Logger log) {
        log.removeAppender(appender);
        
    }
}
