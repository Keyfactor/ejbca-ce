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

import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.protocol.HttpContext;
import org.cesecore.configuration.GdprConfigurationCache;

public class GdprRedactionUtils {
    
    public static final String REDACTED_CONTENT = "<redacted>";
    
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
    
    public static String getLogSafe(final String string, final String identifier, final int endEntityProfileId) {
        return GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii() ? 
                string.replace(identifier, GdprRedactionUtils.REDACTED_CONTENT) : string;
    }
    
    public static String getLogSafe(String string, final List<String> identifiers, final int endEntityProfileId) {
        if (GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii()) {
            for (String identifier : identifiers) {
                string = string.replace(identifier, GdprRedactionUtils.REDACTED_CONTENT);
            }
        }
        return string;
    }
    
    public static Integer getEndEntityProfileId(final HttpServletRequest request) {
        if (request.getAttribute("redact-eepid") instanceof Integer) {
            return (Integer) request.getAttribute("redact-eepid");
        } else {
            return null;
        }
    }
    
    public static void setEndEntityProfileId(final HttpServletRequest request, final int id) {
        request.setAttribute("redact-eepid", id);
    }
    
    public static Integer getEndEntityProfileId(final HttpContext context) {
        if (context.getAttribute("redact-eepid") instanceof Integer) {
            return (Integer) context.getAttribute("redact-eepid");
        } else {
            return null;
        }
    }
    
    public static void setEndEntityProfileId(final HttpContext context, final int id) {
        context.setAttribute("redact-eepid", id);
    }
    
    
    @SuppressWarnings("unchecked")
    public static List<String> getToBeRedacted(final HttpServletRequest request) {
        if (request.getAttribute("redact") instanceof List) {
            return (List<String>) request.getAttribute("redact");
        } else {
            return Collections.EMPTY_LIST;
        }
    }
    
    public static void setToBeRedacted(final HttpServletRequest request, final List<String> toBeRedacted) {
        request.setAttribute("redact", toBeRedacted);
    }
    
    @SuppressWarnings("unchecked")
    public static List<String> getToBeRedacted(final HttpContext context) {
        if (context.getAttribute("redact") instanceof List) {
            return (List<String>) context.getAttribute("redact");
        } else {
            return Collections.EMPTY_LIST;
        }
    }
    
    public static void setToBeRedacted(final HttpContext context, final List<String> toBeRedacted) {
        context.setAttribute("redact", toBeRedacted);
    }

}
