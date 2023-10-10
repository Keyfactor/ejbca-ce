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
package org.cesecore.util;

import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

public class Log4jLogRedactionRedactHandler extends Handler {

    @Override
    public void close() throws SecurityException {
    }

    @Override
    public void flush() {
    }

    @Override
    public void publish(LogRecord logRecord) {        
        // skip messages from INFO or DEBUG i.e. most server logs
        // @see org.ejbca.util.Log4jHandler
        if ( logRecord.getLevel().intValue() >= Level.FINE.intValue() // DEBUG
                && logRecord.getLevel().intValue() <= Level.INFO.intValue()) { // INFO
            return;
        }
        
        // check for global setting
        if (!LogRedactionUtils.redactPii()) {
            return;
        }
        
        // for ERROR and above + TRACE
        logRecord.setMessage(LogRedactionUtils.getRedactedMessage(logRecord.getMessage()));
        if (logRecord.getThrown()!=null) {
            logRecord.setThrown(LogRedactionUtils.getRedactedThrowable(logRecord.getThrown()));
        }
                
    }
    
}
