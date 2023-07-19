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

import org.cesecore.configuration.GdprConfigurationCache;

/**
 * Utility methods for handling/checking PII redaction based on End Entity Profile.
 * Log safe Subject DN and Subject Alt Name are used when logging PII that
 * should be redacted for GDPR purposes.
 */
public class GdprRedactionUtils {
    
    public static final String REDACTED_CONTENT = "<redact>";

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

    public static boolean isRedactPii(final int endEntityProfileId) {
        return GdprConfigurationCache.INSTANCE.getGdprConfiguration(endEntityProfileId).isRedactPii();
    }
}
