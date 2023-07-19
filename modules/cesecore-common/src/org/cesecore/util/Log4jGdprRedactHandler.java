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
import java.util.Arrays;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.keyfactor.util.certificate.DnComponents;

public class Log4jGdprRedactHandler extends Handler {
    
    private static final Pattern SUBJECT_DN_COMPONENTS;
    private static final Pattern SUBJECT_ALT_NAME_COMPONENTS;
    
    static{
        SUBJECT_DN_COMPONENTS = Pattern.compile(getRegexPattern(
                Arrays.asList(DnComponents.getDnObjects(true))), Pattern.CASE_INSENSITIVE);
        
        List<String> sanAttributes = new ArrayList<>();
        sanAttributes.addAll(DnComponents.getAltNameFields());
        sanAttributes.add(DnComponents.URI);
        sanAttributes.add(DnComponents.URI1);
        SUBJECT_ALT_NAME_COMPONENTS = Pattern.compile(getRegexPattern(sanAttributes), Pattern.CASE_INSENSITIVE);
        
        System.out.println("patterns: " + SUBJECT_DN_COMPONENTS.toString() + " :::: " + SUBJECT_ALT_NAME_COMPONENTS.toString());
        
    }
    
    private static String getRegexPattern(List<String> dnParts) {
        StringBuilder regex = new StringBuilder(); 
        regex.append("(");
        for(String dnPart: dnParts) {
            regex.append("(" + dnPart + "=)|");
        }
        regex.deleteCharAt(regex.length()-1);
        regex.append(").*");
        return regex.toString();
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
        
        // check for global setting
        if (!GdprRedactionUtils.redactPii()) {
            return;
        }
        
        // for ERROR and above + TRACE
        logRecord.setMessage(getRedactedMessage(logRecord.getMessage()));
        
        // TODO: redact the exception message but keep stack trace, attempt
//        Throwable t = new Throwable(getRedactedMessage(logRecord.getThrown().getMessage()));
//        t.setStackTrace(logRecord.getThrown().getStackTrace());
//        logRecord.setThrown(t);
                
    }
    
    public static String getRedactedMessage(String message) {
        // print only till start of the PII string cause we can not detect end of a match as we allow whitespace in DN
        Matcher matcher = SUBJECT_DN_COMPONENTS.matcher(message);
        if(matcher.find()) {
            return message.substring(0, matcher.start());
        }
        
        matcher = SUBJECT_ALT_NAME_COMPONENTS.matcher(message);
        if(matcher.find()) {
            return message.substring(0, matcher.start());
        }
        
        return message;
    }

}
