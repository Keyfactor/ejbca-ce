package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateCreateException;
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
    
    @Test
    public void testRedactSubjectDnSanRedact() {
        
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_REDACT_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_REDACT_NAME), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_REDACT_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_REDACT_NAME), GdprRedactionUtils.REDACTED_CONTENT);

    }
    
    @Test
    public void testRedactSubjectDnSanEmpty() {
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_ID), DUMMY_SDN);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_EMPTY_NAME), DUMMY_SDN);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_ID), DUMMY_SAN);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_EMPTY_NAME), DUMMY_SAN);
        GdprConfigurationCache.INSTANCE.updateGdprNodeLocalSettings(true, false);
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
        GdprConfigurationCache.INSTANCE.updateGdprNodeLocalSettings(false, true);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectDnLogSafe(DUMMY_SDN, EEP_LOGPLAIN_NAME), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_ID), GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getSubjectAltNameLogSafe(DUMMY_SAN, EEP_LOGPLAIN_NAME), GdprRedactionUtils.REDACTED_CONTENT);
        
    }
    
    @Test
    public void testRedactionPatterns() {
        assertEquals("SubjectDN redaction pattern mismatch", GdprRedactionUtils.getSubjectDnRedactionPattern(), 
                "((certificationid=)|(description=)|(jurisdictioncountry=)|(jurisdictionstate=)|(jurisdictionlocality=)|"
                + "(role=)|(street=)|(pseudonym=)|(telephonenumber=)|(postaladdress=)|(businesscategory=)|(postalcode=)|"
                + "(unstructuredaddress=)|(unstructuredname=)|(emailaddress=)|(email=)|(dn=)|(uniqueidentifier=)|"
                + "(uid=)|(pid=)|(vid=)|(cn=)|(name=)|(sn=)|(serialnumber=)|(gn=)|(givenname=)|(initials=)|(surname=)|"
                + "(ou=)|(organizationidentifier=)|(st=)|(dc=)|(c=)).*");
        assertEquals("SubjectAltName redaction pattern mismatch", GdprRedactionUtils.getSubjectAltNameRedactionPattern(), 
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
        GdprConfigurationCache.INSTANCE.updateGdprNodeLocalSettings(true, false);
        
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
            assertEquals("Expected same error code in both redacted and original exception", 
                    CesecoreException.getErrorCode(e), ErrorCode.BAD_REQUEST);
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CesecoreException(ErrorCode.BAD_REQUEST, DUMMY_MESSAGE_WITH_SDN);
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertEquals("Expected same error code in both redacted and original exception", 
                    CesecoreException.getErrorCode(e), ErrorCode.BAD_REQUEST);
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CertificateCreateException(ErrorCode.BAD_REQUEST, new IllegalArgumentException(DUMMY_MESSAGE_WITH_SDN));
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertEquals("Expected same error code in both redacted and original exception", 
                    CesecoreException.getErrorCode(e), ErrorCode.BAD_REQUEST);
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertNull("Inner cause exception message is not redacted", t.getCause());
            assertStackTraceEquals(e.getStackTrace(), GdprRedactionUtils.getRedactedThrowable(e).getStackTrace());
        }
        
        try {
            throw new CertificateCreateException(DUMMY_MESSAGE_WITH_SDN,
                    new CADoesntExistsException(DUMMY_MESSAGE_WITH_SDN));
        } catch (CesecoreException e) {
            Throwable t = GdprRedactionUtils.getRedactedThrowable(e);
            log.error("logged: ", t);
            assertEquals("Expected same class for both redacted and original exception", e.getClass(), t.getClass());
            assertFalse("Exception message is not redacted", t.getMessage().contains("OU="));
            assertFalse("Inner cause message is not redacted", t.getCause().getMessage().contains("OU="));
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
        GdprConfigurationCache.INSTANCE.updateGdprNodeLocalSettings(false, false);
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
        GdprConfigurationCache.INSTANCE.updateGdprNodeLocalSettings(true, false);
        
        assertEquals(GdprRedactionUtils.getRedactedMessage(DUMMY_MESSAGE_WITH_SDN), "some message: " + GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getRedactedMessage(null), null);
        assertEquals(GdprRedactionUtils.getRedactedMessage(""), "");
        assertEquals(GdprRedactionUtils.getRedactedMessage("some other message: uri=xyz.abc blah,dnsName=abcd.com"), 
                "some other message: " + GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getRedactedMessage("some other message: dnsName=abcd.com,uri=xyz.abc blah"), 
                "some other message: " + GdprRedactionUtils.REDACTED_CONTENT);
        assertEquals(GdprRedactionUtils.getRedactedMessage("some other message: serialno=123456 subjectemail=asd@we.com"), 
                "some other message: serialno=123456 subject" + GdprRedactionUtils.REDACTED_CONTENT);
        
        // disable redaction
        GdprConfigurationCache.INSTANCE.updateGdprNodeLocalSettings(false, false);
        assertEquals(GdprRedactionUtils.getRedactedMessage(DUMMY_MESSAGE_WITH_SDN), DUMMY_MESSAGE_WITH_SDN);
    }

}
