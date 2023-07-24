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

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.cesecore.configuration.GdprConfigurationCache;

import com.keyfactor.util.certificate.DnComponents;

/**
 * Utility methods for handling/checking PII redaction based on End Entity Profile.
 * Log safe Subject DN and Subject Alt Name are used when logging PII that
 * should be redacted for GDPR purposes.
 */
public class GdprRedactionUtils {
    
    public static final String REDACTED_CONTENT = "<redact>";
    
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
    
    // only for testing
    protected static String getSubjectDnRedactionPattern() {
        return SUBJECT_DN_COMPONENTS.toString();
    }
    
    protected static String getSubjectAltNameRedactionPattern() {
        return SUBJECT_ALT_NAME_COMPONENTS.toString();
    }

    public static String getSubjectDnLogSafe(String subjectDn, int endEntityProfileId) {
        if(GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii()) {
            return REDACTED_CONTENT;
        } else {
            return subjectDn;
        }
    }
    
    public static String getSubjectDnLogSafe(String subjectDn, String endEntityProfileName) {
        if(GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileName).isRedactPii()) {
            return REDACTED_CONTENT;
        } else {
            return subjectDn;
        }
    }
    
    public static String getSubjectAltNameLogSafe(String san, int endEntityProfileId) {
        if(GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii()) {
            return REDACTED_CONTENT;
        } else {
            return san;
        }
    }
    
    public static String getSubjectAltNameLogSafe(String san, String endEntityProfileName) {
        if(GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileName).isRedactPii()) {
            return REDACTED_CONTENT;
        } else {
            return san;
        }
    }
    
    public static boolean redactPii() { // placeholder
        return GdprConfigurationCache.INSTANCE.getGdprConfiguration("").isRedactPii();
    }

    public static boolean isRedactPii(final int endEntityProfileId) {
        return GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii();
    }
    
    public static boolean redactPii() { // placeholder
        return GdprConfigurationCache.INSTANCE.getGdprConfiguration("").isRedactPii();
    }
    
    public static String getRedactedMessage(String message) {
        return getRedactedMessage(message, redactPii());
    }
    
    public static String getRedactedMessage(String message, int endEntityProfileId) {
        return getRedactedMessage(message, 
                GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii());
    }
    
    public static String getRedactedMessage(String message, boolean redactPii) {
        
        if(StringUtils.isEmpty(message) || !redactPii) {
            return message;
        }
        
        // print only till start of the PII string cause we can not detect end of a match as we allow whitespace in DN
        // need to compare SAN before subjectDN as 'name' subjectDN attribute matches with dnsName, rfc822Name etc
        Matcher matcher = SUBJECT_ALT_NAME_COMPONENTS.matcher(message);
        if(matcher.find()) {
            return message.substring(0, matcher.start()) + REDACTED_CONTENT;
        }
        
        matcher = SUBJECT_DN_COMPONENTS.matcher(message);
        if(matcher.find()) {
            return message.substring(0, matcher.start()) + REDACTED_CONTENT;
        }
                
        return message;
    }
    
    /**
     * Redacts the exception message if needed and creates a new exception with redacted message and same stack trace<br>
     * <strong>NOT to be rethrown</strong>, other properties like ErrorCode etc are ignored<br>
     * Always uses String constructor of Exception class
     * 
     * @param thrownException
     * @return
     */
    public static Throwable getRedactedThrowable(Throwable thrownException) {
        return getRedactedThrowable(thrownException, redactPii());
    }
     
    public static Throwable getRedactedThrowable(Throwable thrownException, int endEntityProfileId) {
        return getRedactedThrowable(thrownException, 
                GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii());
    }
    
    private static Throwable getRedactedThrowable(Throwable thrownException, boolean redactPii) {
        if (thrownException==null) {
            return null;
        }
        
        if(!redactPii) {
            return thrownException;
        }
        
        Throwable redactedException;
        try {
            redactedException = thrownException.getClass().getConstructor(String.class)
                    .newInstance((getRedactedMessage(thrownException.getMessage())));
        } catch (InstantiationException | IllegalAccessException | 
                IllegalArgumentException | InvocationTargetException | NoSuchMethodException
                | SecurityException e) {
            return thrownException;
        }
        redactedException.setStackTrace(thrownException.getStackTrace());
        return redactedException;
    }
    

}
