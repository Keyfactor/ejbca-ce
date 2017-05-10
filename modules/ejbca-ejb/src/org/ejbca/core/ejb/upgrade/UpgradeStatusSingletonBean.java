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

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;

import org.apache.log4j.Appender;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
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

    /** Fixed size list (dropping oldest additions when running out of space) to prevent all memory from being consumed if attached process never detaches. */
    private List<LoggingEvent> logged = new LinkedList<LoggingEvent>() {
        private static final long serialVersionUID = 1L;
        private static final int MAX_ENTRIES_IN_LIST = 10000;

        @Override
        public boolean add(final LoggingEvent loggingEvent) {
            // Hard code a filter so we only keep DEBUG and above here in the in-memory buffer
            if (!loggingEvent.getLevel().isGreaterOrEqual(Level.DEBUG)) {
                return false;
            }
            final boolean added = super.add(loggingEvent);
            while (added && size()>MAX_ENTRIES_IN_LIST) {
                super.remove();
            }
            return added;
        }  
    };
    
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
