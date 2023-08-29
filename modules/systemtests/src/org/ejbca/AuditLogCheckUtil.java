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
package org.ejbca;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventTypes;

public class AuditLogCheckUtil {
    
    private static final Logger log = Logger.getLogger(AuditLogCheckUtil.class);
    
    // different params for server and audit log
    // case insensitive: do not use 'CA' here as too short
    private static final String[] IGNORED_ON_LOWERCASE_PREFIXES = 
                        {"issuerdn", "issuer", "cadn", "keyalias", "keyid", "username", 
                                "end entity", 
                                // edge cases from hell
                                "o=anatom", "o=let's encrypt"};
    // "admin ::: CN=blah" -> 'CN' starts at index 10, 'admin' ends at index 4, slack needed 6
    private static final int PREFIXES_SLACK = 10;
    
    public static void detectPiiLogging(List<? extends AuditLogEntry> auditLogsGenerated, 
            Set<String> detectedEventTypes, List<Pattern> compiledPatterns) {
        
        for(AuditLogEntry auditEntry: auditLogsGenerated) {
            
            if (auditEntry.getEventTypeValue().equals(EventTypes.CERT_CTPRECERT_SUBMISSION)) {
                continue;
            }
            
            String auditedAdditionalDetails = getAsString(auditEntry.getMapAdditionalDetails());
            outer:
            for (Pattern p: compiledPatterns) {
                Matcher m = p.matcher(auditedAdditionalDetails);
                if(m.find()) {
                    String wholePrefix = auditedAdditionalDetails.substring(0, m.start()).trim().toLowerCase();
                    for (String str: IGNORED_ON_LOWERCASE_PREFIXES) {
                        int detected = wholePrefix.lastIndexOf(str);
                        if (detected > 0 && 
                                (detected + str.length() + PREFIXES_SLACK > wholePrefix.length()) ) {
                            continue outer;
                        }
                    }
                    detectedEventTypes.add(auditEntry.getEventTypeValue().toString());
                    StringBuilder sb = new StringBuilder();
                    sb.append("type: " + auditEntry.getEventTypeValue().toString());
                    sb.append(", detail1: " + auditEntry.getSearchDetail1()); // may contain test name
                    sb.append(", detail2: " + auditEntry.getSearchDetail2());
                    sb.append(", additional_detail: " + auditedAdditionalDetails);
                    sb.append(", matched with: " + p.toString().substring(0, 10) + ", at index: " + m.start() );
                    log.error("PII logged: " + sb.toString());
                    break;
                }
            }
        }
    }
    
    private static String getAsString(final Map<String,Object> map) {
        final StringBuilder sb = new StringBuilder();
        // we need to validate all keys as Log4jDevice logs all keys too
        for (final Object key : map.keySet()) {
            if (sb.length()!=0) {
                sb.append("; ");
            }
            if (((String)key).equalsIgnoreCase("msg")) {
                String content = (String) map.get(key);
                content = content.toLowerCase();
                if (content.contains("issuerdn")) {
                    int issuerdnStartIndex = content.indexOf("'", content.indexOf("issuerdn"));
                    int issuerdnEndIndex = content.indexOf("'", issuerdnStartIndex+1);
                    content = content.substring(0, issuerdnStartIndex) + content.substring(issuerdnEndIndex, content.length());
                }
                content = content.replace("serialno", "serial:");
                sb.append(key).append(':').append(content);
                continue;
            }
            if (((String)key).equalsIgnoreCase("extendedInformation")) {
                String content = (String) map.get(key);
                content = content.toLowerCase();
                if (content.contains("nameconstraints_permitted")) {
                    content = removeFalsePositiveSubString("nameconstraints_permitted", "]", content);
                }
                if (content.contains("nameconstraints_excluded")) {
                    content = removeFalsePositiveSubString("nameconstraints_excluded", "]", content);
                }
                sb.append(key).append(':').append(content);
                continue;
            }
            if (((String)key).equalsIgnoreCase("publickey") || ((String)key).equalsIgnoreCase("issuerdn")) {
                continue;
            }
            sb.append(key).append(':').append(map.get(key));
        }
        return sb.toString();
    }
    
    private static String removeFalsePositiveSubString(String prefix, String terminateOn, String content) {
        int startIndex = content.indexOf(prefix);
        int endIndex = content.indexOf(terminateOn, startIndex+1);
        return content.substring(0, startIndex) + content.substring(endIndex, content.length());
    }

}
