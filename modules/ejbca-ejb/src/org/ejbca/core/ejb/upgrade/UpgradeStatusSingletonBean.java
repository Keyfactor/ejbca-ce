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

import org.apache.log4j.Level;

import jakarta.ejb.ConcurrencyManagement;
import jakarta.ejb.ConcurrencyManagementType;
import jakarta.ejb.Singleton;
import jakarta.ejb.TransactionManagement;
import jakarta.ejb.TransactionManagementType;

/**
 * Singleton responsible for keep track of a node-local post upgrade.
 * 
 */
@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
@TransactionManagement(TransactionManagementType.BEAN)
public class UpgradeStatusSingletonBean implements UpgradeStatusSingletonLocal {

    private AtomicBoolean postUpgradeInProgress = new AtomicBoolean(false);
    
    /** Fixed size list (dropping oldest additions when running out of space) to prevent all memory from being consumed if attached process never detaches. */
    private List<UpgradeLogEvent> logged = new LinkedList<>() {
        private static final long serialVersionUID = 1L;
        private static final int MAX_ENTRIES_IN_LIST = 10000;

        @Override
        public boolean add(final UpgradeLogEvent loggingEvent) {
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
    public List<UpgradeLogEvent> getLogged() {
        return logged;
    }
    
    @Override
    public void trace(final Object msg) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.TRACE));
       
    }
    
    @Override
    public void debug(final Object msg) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.DEBUG));
        
    }
    
    @Override
    public void debug(final Object msg, final Throwable throwable) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.DEBUG, throwable));
        
    }
    
    @Override
    public void info(final Object msg) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.INFO));
        
    }
    
    @Override
    public void warn(final Object msg) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.WARN));
        
    }
     
    @Override
    public void error(final Object msg) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.ERROR));
        
    }
    
    @Override
    public void error(final Object msg, final Throwable throwable) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.ERROR, throwable));
        
    }
    
    @Override
    public void fatal(final Object msg) {
        logged.add(new UpgradeLogEvent(msg.toString(), Level.FATAL));  
    }
    
}
