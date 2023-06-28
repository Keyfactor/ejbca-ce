package org.cesecore.util;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.cesecore.configuration.GdprConfiguration;
import org.cesecore.configuration.GdprConfigurationCache;
import org.junit.BeforeClass;
import org.junit.Test;

public class GdprRedactionUtilsTest {
    
    private static final String EEP_REDACT_NAME = "EEP_REDACT";
    private static final int EEP_REDACT_ID = 1000;
    
    private static final String EEP_LOGPLAIN_NAME = "EEP_LOGPLAIN";
    private static final int EEP_LOGPLAIN_ID = 1001;
    
    private static final String EEP_EMPTY_NAME = "EMPTY";
    private static final int EEP_EMPTY_ID = 1;
    
    private static final String DUMMY_SDN = "CN=abcd";
    private static final String DUMMY_SAN = "dnsName=abcd.de";
    
    @BeforeClass
    public static void setup() {
        
        final Map<Integer, GdprConfiguration> idToGdprConfigCache = new HashMap<>();
        final Map<String, GdprConfiguration> nameToGdprConfigCache = new HashMap<>();
        
        GdprConfiguration redact = new GdprConfiguration(true);
        GdprConfiguration logPlain = new GdprConfiguration(false);
        
        idToGdprConfigCache.put(EEP_REDACT_ID, redact);
        idToGdprConfigCache.put(EEP_LOGPLAIN_ID, logPlain);
        
        nameToGdprConfigCache.put(EEP_REDACT_NAME, redact);
        nameToGdprConfigCache.put(EEP_LOGPLAIN_NAME, logPlain);
        
        GdprConfigurationCache.INSTANCE.updateGdprCache(idToGdprConfigCache, nameToGdprConfigCache);
    }
    
    @Test
    public void testRedactSubjectDnSanRedact() {
        
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_REDACT_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_REDACT_NAME), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_REDACT_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_REDACT_NAME), GdprRedactionUtils.REDACTED_CONTENT);

    }
    
    @Test
    public void testRedactSubjectDnSanEmpty() {
        
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_NAME), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_NAME), GdprRedactionUtils.REDACTED_CONTENT);

    }
    
    @Test
    public void testRedactSubjectDnSanLogPlain() {
        
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_ID), DUMMY_SDN);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_NAME), DUMMY_SDN);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_ID), DUMMY_SAN);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_NAME), DUMMY_SAN);

    }

}
