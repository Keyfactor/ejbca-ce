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

package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.GdprRedactionUtils;
import org.ejbca.core.ejb.audit.EjbcaAuditorTestSessionRemote;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.Test;

/** 
 * This test is meant to be used as "ant test:runone -Dtest.runone=" before all the systemtests run to test redacted log.<br>
 * We need to set "enable.log.redact=true" at systemtest.properties to allow the functionality.<br>
 * This ensures other systemtests especially the ones meant for testing audt log redaction are not affected.
 */
public class EnableGlobalPiiDataRedactionTest {
    
    private static final Logger log = Logger.getLogger(EnableGlobalPiiDataRedactionTest.class);
        
    protected static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);   
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("EnableGlobalPiiDataRedactionTest");
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    
    private final static String DEVICE_NAME = IntegrityProtectedDevice.class.getSimpleName();
    private static final EjbcaAuditorTestSessionRemote ejbcaAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaAuditorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static final String CUSTOM_LOG_MESSAGE = "EnableGlobalPiiDataRedactionTest_CustomLogMessage";
        
    @Test
    public void setRedactEnfoced() throws Exception {
        if (!SystemTestsConfiguration.getEnableLogRedact()) {
            return;
        }
       GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
       globalCesecoreConfiguration.setRedactPiiEnforced(true);
       globalConfigurationSession.saveConfiguration(admin, globalCesecoreConfiguration);
       
       // used to mark the start of SystemTest
       caAdminSession.customLog(admin, "check", null, admin.getUniqueId(), 
               null, CUSTOM_LOG_MESSAGE, EjbcaEventTypes.CUSTOMLOG_INFO);
       
    }
    
    @Test
    public void testAuditLogPiiDataWithCompulsoryRedaction() throws Exception {
        
        String[] patternsToMatch = new String[] { GdprRedactionUtils.getSubjectDnRedactionPattern(),
                GdprRedactionUtils.getSubjectAltNameRedactionPattern(), "\\WMI[a-zA-Z0-9]{10}"}; // TODO: hex
        List<Pattern> compiledPatterns =  new ArrayList<>();
        Stream.of(patternsToMatch).map(Pattern::compile).map(compiledPatterns::add);
        
        final List<Object> startMarkerParams = new ArrayList<>();
        startMarkerParams.add("CUSTOMLOG_INFO");
        startMarkerParams.add("%" + CUSTOM_LOG_MESSAGE + "%");
        List<? extends AuditLogEntry> customMessageOccurences = ejbcaAuditorSession.selectAuditLog(admin, DEVICE_NAME, 0, 10, 
                " a.eventType=?0 and a.additionalDetails LIKE ?1", "a.timeStamp DESC", startMarkerParams);
        if (customMessageOccurences.isEmpty()) {
            fail("failed to detect SystemTest starting marker");
        }
        
        long allTestsStartTime = customMessageOccurences.get(0).getTimeStamp();
        String[] auditEventPatternsToVerify = new String[] { 
                "APPROVAL%", 
                "KEYRECOVERY%", 
                "PUBLISHER_STORE%", 
                "RA_%ENDENTITY",
                "RA_USERDATASOURCEFETCHDATA",
                "REVOKE_UNREVOKEPUBLISH",
                "CERT_%"
                };
        String auditEventPatternsToIgnore = "%PROFILE%";
        
        Set<String> detectedEventTypes = new HashSet<>();
        for (int i=0; i<auditEventPatternsToVerify.length; i++) {
            final List<Object> parameters = new ArrayList<>();
            parameters.add(allTestsStartTime);
            parameters.add(auditEventPatternsToVerify[i]);
            parameters.add(auditEventPatternsToIgnore);
            List<? extends AuditLogEntry> auditLogsGenerated = null;
                 
            int offset = 0;
            while (true && offset < 100_000) {
                auditLogsGenerated =  ejbcaAuditorSession.selectAuditLog(admin, DEVICE_NAME, offset, 1000, 
                        "a.timeStamp > ?0" +
                        " and a.eventType LIKE ?1 and a.eventType NOT LIKE ?2", null, parameters);
                if(auditLogsGenerated.isEmpty()) {
                    break;
                }
                offset += 1000;
                detectPiiLogging(auditLogsGenerated, detectedEventTypes, compiledPatterns);
            }
        }
        
        assertTrue("Found AUDIT logged PII data in: " + detectedEventTypes, detectedEventTypes.isEmpty());
    }
    
    private void detectPiiLogging(List<? extends AuditLogEntry> auditLogsGenerated, 
            Set<String> detectedEventTypes, List<Pattern> compiledPatterns) {
        
        
        for(AuditLogEntry auditEntry: auditLogsGenerated) {
            String auditedAdditionalDetails = getAsString(auditEntry.getMapAdditionalDetails()).toLowerCase();
            for (Pattern p: compiledPatterns) {
                if(p.matcher(auditedAdditionalDetails).find()) {
                    detectedEventTypes.add(auditEntry.getEventTypeValue().toString());
                    StringBuilder sb = new StringBuilder();
                    sb.append("type: " + auditEntry.getEventTypeValue().toString());
                    sb.append(", detail1: " + auditEntry.getSearchDetail1()); // may contain test name
                    sb.append(", detail2: " + auditEntry.getSearchDetail2());
                    sb.append(", additional_detail: " + auditedAdditionalDetails);
                    log.error("PII logged: " + sb.toString());
                    break;
                }
            }
        }
    }
    
    private static String getAsString(final Map<String,Object> map) {
        final StringBuilder sb = new StringBuilder();
        if (map.size() == 1 && map.containsKey("msg")) {
            final String ret = (String) map.get("msg");
            if (ret != null) {
                return ret;
            }
        }
        for (final Object key : map.keySet()) {
            if (sb.length()!=0) {
                sb.append("; ");
            }
            sb.append(key).append('=').append(map.get(key));
        }
        return sb.toString();
    }
    
}
