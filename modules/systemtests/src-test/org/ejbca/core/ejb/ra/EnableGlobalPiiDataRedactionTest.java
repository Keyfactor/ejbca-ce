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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.AuditLogCheckUtil;
import org.ejbca.ServerLogCheckUtil;
import org.ejbca.ServerLogCheckUtil.ServerLogRecord;
import org.ejbca.core.ejb.audit.EjbcaAuditorTestSessionRemote;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;

/** 
 * This test is meant to be used as "ant test:runone -Dtest.runone=" before all the systemtests run to test redacted log.<br>
 * We need to set "enable.log.redact=true" at systemtest.properties to allow the functionality.<br>
 * This ensures other systemtests especially the ones meant for testing audit log redaction are not affected.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EnableGlobalPiiDataRedactionTest {
    
    private static final Logger log = Logger.getLogger(EnableGlobalPiiDataRedactionTest.class);
        
    protected static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);   
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("EnableGlobalPiiDataRedactionTest");
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    
    private final static String DEVICE_NAME = IntegrityProtectedDevice.class.getSimpleName();
    private static final EjbcaAuditorTestSessionRemote ejbcaAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EjbcaAuditorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private static final String CUSTOM_LOG_MESSAGE = "EnableGlobalPiiDataRedactionTest_CustomLogMessage";
    private static final String CA_CREATED_WITH_DN_MARKER = "Created CA with subject DN:";
    private static final Set<String> ADMIN_DN_LIST = new HashSet<>();
        
    @BeforeClass
    public static void isEnabledAuditLogRedactionTest() {
        assertEquals("New cesecore audit event may need to tested for PII redaction.", EventTypes.values().length, 71);
        assertEquals("New ejbca audit event may need to tested for PII redaction.", EjbcaEventTypes.values().length, 65);
        
        // set enable.log.redact=true in conf/systemtest.properties
        assumeTrue("Skipping this test as it is not meant for normal system tests", SystemTestsConfiguration.getEnableLogRedact());
    }
        
    @Test
    public void setRedactEnforced() throws Exception {
        if (!SystemTestsConfiguration.getEnableLogRedact()) {
            return;
        }
       GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
       if (globalCesecoreConfiguration.getRedactPiiEnforced()) {
           log.error("Redaction is enabled already.");
           return;
       }
       
       globalCesecoreConfiguration.setRedactPiiEnforced(true);
       globalConfigurationSession.saveConfiguration(admin, globalCesecoreConfiguration);
       
       globalCesecoreConfiguration = (GlobalCesecoreConfiguration)
               globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
       log.error("Redaction settings: " + globalCesecoreConfiguration.getRedactPiiEnforced());
       
       // used to mark the start of SystemTest
       caAdminSession.customLog(admin, "check", null, admin.getUniqueId(), 
               null, CUSTOM_LOG_MESSAGE, EjbcaEventTypes.CUSTOMLOG_INFO);
       
    }
    
    @Test
    public void testAuditLogPiiDataWithCompulsoryRedaction() throws Exception {
        
        String[] patternsToMatch = new String[] { LogRedactionUtils.getSubjectDnRedactionPattern().replace("|(c=)", ""),
                LogRedactionUtils.getSubjectAltNameRedactionPattern(), ServerLogCheckUtil.BASE64_LOGGINGS_PATTERN};
//        matches all -> ".*MI[EIM]{1}[a-zA-Z0-9]{12}.*" for wildfly filter
//        finds all -> "MI[EIM]{1}[a-zA-Z0-9]{12}" without .* at both end
//        examples returning true:        
//        "asdaMIIowe345ht11asdadqw" -> bad match
//        "MIIowe345ht11asdadqw"
//        " MIIowe345ht11asdadqw"
//        "xxx MIIowe345ht11asdadqw"
//        "xxx:MIIowe345ht11asdadqw"
//        "yyy xxx : MIIowe345ht11asdadqw"
//        "yyy xxx:MIIowe345ht11asdadqw"
        List<Pattern> compiledPatterns =  new ArrayList<>();
        for (String p: patternsToMatch) {
            compiledPatterns.add(Pattern.compile(p, Pattern.CASE_INSENSITIVE));
        }
        
        final List<Object> startMarkerParams = new ArrayList<>();
        startMarkerParams.add("CUSTOMLOG_INFO");
        startMarkerParams.add("%" + CUSTOM_LOG_MESSAGE + "%");
        List<? extends AuditLogEntry> customMessageOccurences = ejbcaAuditorSession.selectAuditLogNoAuth(admin, DEVICE_NAME, 0, 10, 
                " a.eventType=?0 and a.additionalDetails LIKE ?1", "a.timeStamp DESC", startMarkerParams);
        if (customMessageOccurences.isEmpty()) {
            fail("failed to detect SystemTest starting marker");
        }
        log.error("Detected marker at: " + new Date(customMessageOccurences.get(0).getTimeStamp()));
        
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
                auditLogsGenerated =  ejbcaAuditorSession.selectAuditLogNoAuth(admin, DEVICE_NAME, offset, 1000, 
                        "a.timeStamp > ?0" +
                        " and a.eventType LIKE ?1 and a.eventType NOT LIKE ?2", "a.timeStamp DESC", parameters);
                if(auditLogsGenerated.isEmpty()) {
                    break;
                }
                offset += 1000;
                auditLogsGenerated.forEach(a -> ADMIN_DN_LIST.add(a.getAuthToken()));
                AuditLogCheckUtil.detectPiiLogging(auditLogsGenerated, detectedEventTypes, compiledPatterns);
            }
        }
        
        assertTrue("Found audit logged PII data in: " + detectedEventTypes, detectedEventTypes.isEmpty());
    }    
    
    @Test
    public void testServerLogPiiDataWithCompulsoryRedaction() throws Exception {
        String logFilePath = SystemTestsConfiguration.getServerLogFilePath();
        
        int linesRead = 0;
        int linesReadEjbca = 0;
        int linesReadCesecore = 0;
        int linesReadKeyFactor = 0;
        Map<String, Set<String>> loggedPiiLines = new HashMap<>();
        Set<String> issuerDns = new HashSet<>();
        
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(logFilePath));
            String line = reader.readLine();

            while (line != null) {
                linesRead++;
                if (line.contains("org.ejbca")) {
                    linesReadEjbca++;
                }
                if (line.contains("org.cesecore")) {
                    linesReadCesecore++;
                }
                if (line.contains("com.keyfactor")) {
                    linesReadKeyFactor++;
                }
                line = reader.readLine();
                
                ServerLogRecord logRecord = ServerLogCheckUtil.parseServerLogRecord(line);
                
                if (logRecord!=null && logRecord.getMessage()!=null 
                        && logRecord.getMessage().contains(CA_CREATED_WITH_DN_MARKER)) {
                    String issuerDn = logRecord.getMessage().substring(
                            logRecord.getMessage().indexOf(CA_CREATED_WITH_DN_MARKER) 
                            + CA_CREATED_WITH_DN_MARKER.length() + 1).strip();
                    issuerDns.add(issuerDn);
                    String transformedIssuerDn = CertTools.stringToBCDNString(StringTools.strip(issuerDn));
                    issuerDns.add(transformedIssuerDn);
                    if(issuerDn.endsWith("C=SE")) {
                        issuerDn = "C=SE," + issuerDn.replace(",C=SE", "");
                        issuerDns.add(issuerDn);
                    }
                }
                if (logRecord==null || logRecord.isWhiteListed(issuerDns, ADMIN_DN_LIST)) {
                    continue;
                }
                
                if (!loggedPiiLines.containsKey(logRecord.getClassName())) {
                    loggedPiiLines.put(logRecord.getClassName(), new HashSet<>());
                }
                loggedPiiLines.get(logRecord.getClassName()).add(logRecord.getMethodName() + " : " + logRecord.getLineNo());
                
            }

            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        log.error("processed log lines: " + linesRead);
        log.error("processed log lines from keyfactor packages: " + linesReadKeyFactor);
        log.error("processed log lines from cesecore packages: " + linesReadCesecore);
        log.error("processed log lines from ejbca packages: " + linesReadEjbca);
        log.error("processed issuer dn: " + issuerDns);
        log.error("processed admin dn: " + ADMIN_DN_LIST);
        
        StringBuilder sb = new StringBuilder();
        for (String key: loggedPiiLines.keySet()) {
            sb.append("    " + key + "\n");
            for (String entry: loggedPiiLines.get(key)) {
                sb.append("        " + entry + "\n");
            }
        }
        
        String piiLogged = sb.toString();
        if (!piiLogged.isEmpty()) {
            if (issuerDns.isEmpty()) {
                // please do not delete
                // CaSessionBean.addCA: log.info("Created CA with subject DN: " + ca.getSubjectDN());
                log.error("Detected no logged issuer DNs. Expected log from CaSessionBean with message: " + CA_CREATED_WITH_DN_MARKER);
            }
            log.error("Detected PII instances: ");
            log.error(piiLogged);
        } else {
            log.error("Detected no PII instances");
        }
        
        assertTrue("Expected no PII to be logged after ignoring whitelisted ones.", loggedPiiLines.isEmpty());
        
    }
    
}
