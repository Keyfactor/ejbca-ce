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

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.GdprRedactionUtils;
import org.junit.BeforeClass;
import org.junit.Test;

public class AuditLogCheckUtilTest {
        
    private static List<Pattern> compiledPatterns;
    
    @BeforeClass
    public static void setup() {
        String[] patternsToMatch = new String[] { GdprRedactionUtils.getSubjectDnRedactionPattern().replace("|(c=)", ""),
                GdprRedactionUtils.getSubjectAltNameRedactionPattern(), "MI[EIMH]{1}[a-zA-Z0-9]{12}"};
        compiledPatterns =  new ArrayList<>();
        for (String p: patternsToMatch) {
            compiledPatterns.add(Pattern.compile(p, Pattern.CASE_INSENSITIVE));
        }
    }
    
    @Test
    public void test1() {
        Map<String, Object> additionalDetails1 = new HashMap<>();
        additionalDetails1.put("msg", "some message issuer=CN=qwert keyid izzuwo/x8phfdeoqf+ywpkef8ag=");
        AuditLogEntry auditLogEntry1 = new AuditRecordData("", 
                100L, 100L, EventTypes.CERT_REVOKED, EventStatus.SUCCESS, 
                "CN=abcd", ServiceTypes.CORE, ModuleTypes.CERTIFICATE, null, null, null, additionalDetails1);
        
        Map<String, Object> additionalDetails2 = new HashMap<>();
        additionalDetails2.put("msg", "some message issuerDn 'CN=qwert'");
        AuditLogEntry auditLogEntry2 = new AuditRecordData("", 
                100L, 100L, EventTypes.CERT_REVOKED, EventStatus.SUCCESS, 
                "CN=abcd", ServiceTypes.CORE, ModuleTypes.CERTIFICATE, null, null, null, additionalDetails2);
        
        Map<String, Object> additionalDetails3 = new HashMap<>();
        additionalDetails3.put("msg", "some message username 'CN=qwert' keyid 'cn=rsaca' kealaias 'CN=asdad,O=oiu'");
        additionalDetails3.put("issuerdn", "CN=qwert");
        AuditLogEntry auditLogEntry3 = new AuditRecordData("", 
                100L, 100L, EventTypes.CERT_REVOKED, EventStatus.SUCCESS, 
                "CN=abcd", ServiceTypes.CORE, ModuleTypes.CERTIFICATE, null, null, null, additionalDetails3);
        
        Map<String, Object> additionalDetails4 = new HashMap<>();
        additionalDetails4.put("extendedInformation", "[version:4.0], "
                + "[type:0], [subjectdirattributes:], [maxfailedloginattempts:-1], [remainingloginattempts:-1], "
                + "[nameconstraints_permitted:dNSName:exampleinc.com;rfc822Name:mail.example;rfc822Name:user@host.com;"
                + "iPAddress:0a000000ff000000;iPAddress:20010db8000000000000000000000000ffffffff000000000000000000000000], "
                + "[nameconstraints_excluded:dNSName:forbidden.example.com;rfc822Name:postmaster@mail.example;"
                + "iPAddress:0a010000ffff0000;iPAddress:20050ac7000000000000000000000000ffffffffffffffff0000000000000000;"
                + "directoryName:C=SE,O=PrimeKey,CN=example.com;directoryName:C=SE,CN=spacing], [customdata_ENDTIME:2y]};");
        additionalDetails4.put("issuerdn", "CN=qwert");
        AuditLogEntry auditLogEntry4 = new AuditRecordData("", 
                100L, 100L, EventTypes.CERT_STORED, EventStatus.SUCCESS, 
                "CN=abcd", ServiceTypes.CORE, ModuleTypes.CERTIFICATE, null, null, null, additionalDetails4);
        
        List<AuditLogEntry> logEntries = new ArrayList<>();
        logEntries.add(auditLogEntry1);
        logEntries.add(auditLogEntry2);
        logEntries.add(auditLogEntry3);
        logEntries.add(auditLogEntry4);
        
        Set<String> detectedEventTypes = new HashSet<>();
        
        AuditLogCheckUtil.detectPiiLogging(logEntries, detectedEventTypes, compiledPatterns);
        assertTrue("Should not detect any false positive events.", detectedEventTypes.isEmpty());
        
        
    }

}
