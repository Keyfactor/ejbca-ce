package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.configuration.LogRedactionConfiguration;
import org.cesecore.configuration.LogRedactionConfigurationCache;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

public class LogRedactionUtilsTest {
    
    private static final Logger log = Logger.getLogger(LogRedactionUtilsTest.class);
    
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
        
        final Map<Integer, LogRedactionConfiguration> idToLogRedactionConfigCache = new HashMap<>();
        final Map<String, LogRedactionConfiguration> nameToLogRedactionConfigCache = new HashMap<>();
        
        LogRedactionConfiguration redact = new LogRedactionConfiguration(true);
        LogRedactionConfiguration logPlain = new LogRedactionConfiguration(false);
        
        idToLogRedactionConfigCache.put(EEP_REDACT_ID, redact);
        idToLogRedactionConfigCache.put(EEP_LOGPLAIN_ID, logPlain);
        
        nameToLogRedactionConfigCache.put(EEP_REDACT_NAME, redact);
        nameToLogRedactionConfigCache.put(EEP_LOGPLAIN_NAME, logPlain);
        
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionCache(idToLogRedactionConfigCache, nameToLogRedactionConfigCache);
    }
    
    @Test
    public void testRedactSubjectDnSanRedact() {
        
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_REDACT_ID), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_REDACT_NAME), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_REDACT_ID), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_REDACT_NAME), LogRedactionUtils.REDACTED_CONTENT);

    }
    
    @Test
    public void testRedactSubjectDnSanEmpty() {
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_ID), DUMMY_SDN);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_NAME), DUMMY_SDN);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_ID), DUMMY_SAN);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_NAME), DUMMY_SAN);
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionNodeLocalSettings(true, false);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_ID), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_NAME), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_ID), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_NAME), LogRedactionUtils.REDACTED_CONTENT);

    }
    
    @Test
    public void testRedactSubjectDnSanLogPlain() {
        
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_ID), DUMMY_SDN);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_NAME), DUMMY_SDN);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_ID), DUMMY_SAN);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_NAME), DUMMY_SAN);
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionNodeLocalSettings(false, true);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_ID), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_NAME), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_ID), LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_NAME), LogRedactionUtils.REDACTED_CONTENT);
        
    }
    
    @Test
    public void testRedactionPatterns() {
        assertEquals("SubjectDN redaction pattern mismatch", LogRedactionUtils.getSubjectDnRedactionPattern(),
                "((certificationid=)|(description=)|(jurisdictioncountry=)|(jurisdictionstate=)|(jurisdictionlocality=)|"
                + "(role=)|(street=)|(pseudonym=)|(telephonenumber=)|(postaladdress=)|(businesscategory=)|(postalcode=)|"
                + "(unstructuredaddress=)|(unstructuredname=)|(emailaddress=)|(e=)|(email=)|(dn=)|(uniqueidentifier=)|"
                + "(uid=)|(pid=)|(vid=)|(cn=)|(name=)|(sn=)|(serialnumber=)|(gn=)|(givenname=)|(initials=)|(surname=)|"
                + "(t=)|(ou=)|(organizationidentifier=)|(o=)|(l=)|(st=)|(dc=)|(c=)).*");
        assertEquals("SubjectAltName redaction pattern mismatch", LogRedactionUtils.getSubjectAltNameRedactionPattern(),
                "((OTHERNAME=)|(RFC822NAME=)|(DNSNAME=)|(IPADDRESS=)|(X400ADDRESS=)|(DIRECTORYNAME=)|(EDIPARTYNAME=)|"
                + "(UNIFORMRESOURCEID=)|(REGISTEREDID=)|(UPN=)|(GUID=)|(KRB5PRINCIPAL=)|(PERMANENTIDENTIFIER=)|(XMPPADDR=)|"
                + "(SRVNAME=)|(SUBJECTIDENTIFICATIONMETHOD=)|(FASCN=)|(UNIFORMRESOURCEIDENTIFIER=)|(URI=)).*");
    }
    
    private void dummy() throws CesecoreException {
        throw new CesecoreException(DUMMY_MESSAGE_WITH_SDN);
    }
    
    public static void assertStackTraceEquals(StackTraceElement[] stackTraceExpected, StackTraceElement[] stackTraceOriginal) {
        assertEquals("Stack trace length mismatch", stackTraceExpected.length, stackTraceOriginal.length);
        for (int i=0; i<stackTraceExpected.length; i++) {
            assertEquals("Stack trace mismatch at index: " + i, stackTraceExpected[i].toString(), stackTraceOriginal[i].toString());
        }
    }
    
    @Test
    public void testRedactException() {
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionNodeLocalSettings(true, false);
        
        try {
            throw new CesecoreException(DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t); // ensure logging works
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CesecoreException();
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertNull("Exception message is not null", t.getMessage());
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            dummy();
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CesecoreException(ErrorCode.BAD_REQUEST, DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertEquals("Expected same error code in both redacted and original exception", 
                    CesecoreException.getErrorCode(e), ErrorCode.BAD_REQUEST);
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CesecoreException(ErrorCode.BAD_REQUEST, DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertEquals("Expected same error code in both redacted and original exception", 
                    CesecoreException.getErrorCode(e), ErrorCode.BAD_REQUEST);
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CertificateCreateException(ErrorCode.BAD_REQUEST, new IllegalArgumentException(DUMMY_MESSAGE_WITH_SDN));
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertEquals("Expected same error code in both redacted and original exception", 
                    CesecoreException.getErrorCode(e), ErrorCode.BAD_REQUEST);
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertNull("Inner cause exception message is not redacted", t.getCause());
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CertificateCreateException(DUMMY_MESSAGE_WITH_SDN,
                    new CADoesntExistsException(DUMMY_MESSAGE_WITH_SDN));
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertFalse("Inner cause message is not redacted", t.getCause().getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
                
        // EJBCA external exceptions
        try {
            throw new IllegalArgumentException(DUMMY_MESSAGE_WITH_SDN);
        } catch (IllegalArgumentException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new IllegalArgumentException();
        } catch (IllegalArgumentException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertNull("Exception message is not null", t.getMessage());
            assertStackTraceEquals(e.getStackTrace(), LogRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        // disable redaction
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionNodeLocalSettings(false, false);
        try {
            throw new CesecoreException(DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            assertEquals("Expected same instance in redacted and original exception", e, t);
        }
        
        try {
            throw new IllegalArgumentException(DUMMY_MESSAGE_WITH_SDN);
        } catch (IllegalArgumentException e) {
            Throwable t = LogRedactionUtils.getRedactedThrowable(e);
            assertEquals("Expected same instance in redacted and original exception", e, t);
        }
    }
    
    @Test
    public void testRedactMessage() {
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionNodeLocalSettings(true, false);
        
        assertEquals(LogRedactionUtils.getRedactedMessage(DUMMY_MESSAGE_WITH_SDN), "some message: " + LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getRedactedMessage(null), null);
        assertEquals(LogRedactionUtils.getRedactedMessage(""), "");
        assertEquals(LogRedactionUtils.getRedactedMessage("some other message: uri=xyz.abc blah,dnsName=abcd.com"),
                "some other message: " + LogRedactionUtils.REDACTED_CONTENT);
        assertEquals(LogRedactionUtils.getRedactedMessage("some other message: dnsName=abcd.com,uri=xyz.abc blah"),
                "some other message: " + LogRedactionUtils.REDACTED_CONTENT);
        
        // disable redaction
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionNodeLocalSettings(false, false);
        assertEquals(LogRedactionUtils.getRedactedMessage(DUMMY_MESSAGE_WITH_SDN), DUMMY_MESSAGE_WITH_SDN);
    }

}
