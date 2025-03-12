/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.apache.log4j.Level;

/**
 * Represents a logging event, specifically to be used during upgrades. 
 */
public class UpgradeLogEvent {

    private final Level level;
    private final String message;
    private final long timestamp;
    private final Throwable throwable;
    
    public UpgradeLogEvent(final String message, final Level level) {
        this.level = level;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
        this.throwable = null;
    }
    
    public UpgradeLogEvent(final String message, final Level level, Throwable throwable) {
        this.level = level;
        this.message = message;
        this.timestamp = System.currentTimeMillis();
        this.throwable = throwable;
    }
    

    public Level getLevel() {
        return level;
    }

    public String getMessage() {
        return message;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public Throwable getThrowable() {
        return throwable;
    }
}
