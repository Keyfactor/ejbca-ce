package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.configuration.GdprConfiguration;
import org.cesecore.configuration.GdprConfigurationCache;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

public class GdprRedactionUtilsTest {
    
    private static final Logger log = Logger.getLogger(GdprRedactionUtilsTest.class);
    
    private static final String EEP_REDACT_NAME = "EEP_REDACT";
    private static final int EEP_REDACT_ID = 1000;
    
    private static final String EEP_LOGPLAIN_NAME = "EEP_LOGPLAIN";
    private static final int EEP_LOGPLAIN_ID = 1001;
    
    private static final String EEP_EMPTY_NAME = "EMPTY";
    private static final int EEP_EMPTY_ID = 1;
    
    private static final String DUMMY_SDN = "CN=abcd";
    private static final String DUMMY_SAN = "dnsName=abcd.de";
    private static final String DUMMY_MESSAGE_WITH_SDN = "some message: CN=abcd,OU=xyz blah";
    
    @Before
    public void setup() {
        
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
    
    private void setNoRedaction() {
        
        final Map<Integer, GdprConfiguration> idToGdprConfigCache = new HashMap<>();
        final Map<String, GdprConfiguration> nameToGdprConfigCache = new HashMap<>();
        
        GdprConfiguration logPlain = new GdprConfiguration(false);
        
        idToGdprConfigCache.put(0, logPlain);        
        nameToGdprConfigCache.put("", logPlain);
        
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
    
    @Test
    public void testRedactionPatterns() {
        assertEquals("SubjectDN redaction pattern mismatch", GdprRedactionUtils.getSubjectDnRedactionPattern(), 
                "((certificationid=)|(description=)|(jurisdictioncountry=)|(jurisdictionstate=)|(jurisdictionlocality=)|"
                + "(role=)|(street=)|(pseudonym=)|(telephonenumber=)|(postaladdress=)|(businesscategory=)|(postalcode=)|"
                + "(unstructuredaddress=)|(unstructuredname=)|(emailaddress=)|(e=)|(email=)|(dn=)|(uniqueidentifier=)|"
                + "(uid=)|(pid=)|(vid=)|(cn=)|(name=)|(sn=)|(serialnumber=)|(gn=)|(givenname=)|(initials=)|(surname=)|"
                + "(t=)|(ou=)|(organizationidentifier=)|(o=)|(l=)|(st=)|(dc=)|(c=)).*");
        assertEquals("SubjectAltName redaction pattern mismatch", GdprRedactionUtils.getSubjectAltNameRedactionPattern(), 
                "((OTHERNAME=)|(RFC822NAME=)|(DNSNAME=)|(IPADDRESS=)|(X400ADDRESS=)|(DIRECTORYNAME=)|(EDIPARTYNAME=)|"
                + "(UNIFORMRESOURCEID=)|(REGISTEREDID=)|(UPN=)|(GUID=)|(KRB5PRINCIPAL=)|(PERMANENTIDENTIFIER=)|(XMPPADDR=)|"
                + "(SRVNAME=)|(SUBJECTIDENTIFICATIONMETHOD=)|(FASCN=)|(UNIFORMRESOURCEIDENTIFIER=)|(URI=)).*");
    }
    
    private void dummy() throws CesecoreException {
        throw new CesecoreException(DUMMY_MESSAGE_WITH_SDN);
    }
    
    private void assertStackTraceEquals(StackTraceElement[] stackTraceExpected, StackTraceElement[] stackTraceOriginal) {
        assertEquals("Stack trace length mismatch", stackTraceExpected.length, stackTraceOriginal.length);
        for (int i=0; i<stackTraceExpected.length; i++) {
            assertEquals("Stack trace mismatch at index: " + i, stackTraceExpected[i].toString(), stackTraceOriginal[i].toString());
        }
    }
    
    @Test
    public void testRedactException() {
        // TODO: set redactPii true globally EJBCAINTER-535
        
        try {
            throw new CesecoreException(DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t); // ensure logging works
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CesecoreException();
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertNull("Exception message is not null", t.getMessage());
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            dummy();
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CesecoreException(ErrorCode.BAD_REQUEST, DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        // EJBCA external exceptions
        try {
            throw new IllegalArgumentException(DUMMY_MESSAGE_WITH_SDN);
        } catch (IllegalArgumentException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertNull("Exception message is not null", t.getMessage());
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        // disable redaction
        setNoRedaction();
        try {
            throw new CesecoreException(DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            assertEquals("Expected same instance in redacted and original exception", e, t);
        }
        
        try {
            throw new IllegalArgumentException(DUMMY_MESSAGE_WITH_SDN);
        } catch (IllegalArgumentException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            assertEquals("Expected same instance in redacted and original exception", e, t);
        }
    }
    
    @Test
    public void testRedactMessage() {
        // TODO: set redactPii true globally EJBCAINTER-535
        
        assertEquals(GdprRedactionUtils.getRedactedMessage(DUMMY_MESSAGE_WITH_SDN), "some message: ");
        assertEquals(GdprRedactionUtils.getRedactedMessage(null), null);
        assertEquals(GdprRedactionUtils.getRedactedMessage(""), "");
        assertEquals(GdprRedactionUtils.getRedactedMessage("some other message: uri=xyz.abc blah,dnsName=abcd.com"), "some other message: ");
        assertEquals(GdprRedactionUtils.getRedactedMessage("some other message: dnsName=abcd.com,uri=xyz.abc blah"), "some other message: ");
        
        // disable redaction
        setNoRedaction();
        assertEquals(GdprRedactionUtils.getRedactedMessage(DUMMY_MESSAGE_WITH_SDN), DUMMY_MESSAGE_WITH_SDN);
    }

}
