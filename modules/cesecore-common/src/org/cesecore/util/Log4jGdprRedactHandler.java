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

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import org.apache.commons.lang.StringUtils;

import com.keyfactor.util.certificate.DnComponents;

public class Log4jGdprRedactHandler extends Handler {
    
    private static final List<String> SUBJECT_DN_COMPONENTS;
    private static final List<String> SUBJECT_ALT_NAME_COMPONENTS;
    
    static{
        SUBJECT_DN_COMPONENTS = new ArrayList<>();
        for(String dnPart: DnComponents.getDnObjects(true)) {
            SUBJECT_DN_COMPONENTS.add(dnPart + "=");
        }
        SUBJECT_ALT_NAME_COMPONENTS = new ArrayList<>();
        for(String sanPart: DnComponents.getAltNameFields()) {
            SUBJECT_ALT_NAME_COMPONENTS.add(sanPart + "=");
        }
    }

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
        
        // TODO: check for global setting
        
        // for ERROR and above + TRACE
        for(String dnPart: SUBJECT_DN_COMPONENTS) {
            int matchIndex = StringUtils.indexOfIgnoreCase(logRecord.getMessage(), dnPart);
            if(matchIndex>0) {
                logRecord.setMessage(logRecord.getMessage().substring(0, matchIndex));
                return;
            }
        }
        
        for(String sanPart: SUBJECT_ALT_NAME_COMPONENTS) {
            int matchIndex = StringUtils.indexOfIgnoreCase(logRecord.getMessage(), sanPart);
            if(matchIndex>0) {
                logRecord.setMessage(logRecord.getMessage().substring(0, matchIndex));
                return;
            }
        }
                
    }

}
