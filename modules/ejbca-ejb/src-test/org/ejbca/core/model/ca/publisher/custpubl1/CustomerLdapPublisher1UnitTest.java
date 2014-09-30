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
package org.ejbca.core.model.ca.publisher.custpubl1;

import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.custpubl1.CustomerLdapPublisher1.LogInfo;
import static org.junit.Assert.*;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test case for the CustomerLdapPublisher1.
 *
 * This is a unit test and does not require EJBCA nor an LDAP catalog to be
 * running.
 *
 * @version $Id$
 */
public class CustomerLdapPublisher1UnitTest {

    private static final AuthenticationToken ANY_ADMIN = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateSamplerCustomPublisherUnitTest"));
    private static final byte[] ANY_BYTEARRAY = new byte[0];
    private static final String ANY_CAFP = "44447777111";
    private static final int ANY_NUMBER = 4711;
    private static final String ANY_SUBJECTDN = "CN=User";
    private static final Certificate NULL_CERTIFICATE = null;
    private static final String ANY_USERNAME = "user1";
    private static final String ANY_PASSWORD = "foo123!";
    private static final String ANY_TAG = "any tag";
    private static final byte[] CERT_BYTES = Base64.decode(("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
            + "AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx" + "ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
            + "ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2" + "Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
            + "QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX" + "YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
            + "BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu" + "XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
            + "9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw" + "eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
            + "nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());
    private static final String CERT_ISSUERDN = "CN=Test,O=Test,C=SE";
    private static final byte[] ANY_CERT_BYTES = CERT_BYTES;
    
    
    private static final byte[] CRL_BYTES = Base64.decode(("MIIDEzCCAnwCAQEwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UEAxMGVGVzdENBMQ8w"
            + "DQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFFw0wMjAxMDMxMjExMTFaFw0wMjAx" + "MDIxMjExMTFaMIIB5jAZAggfi2rKt4IrZhcNMDIwMTAzMTIxMDUxWjAZAghAxdYk"
            + "7mJxkxcNMDIwMTAzMTIxMDUxWjAZAgg+lCCL+jumXxcNMDIwMTAzMTIxMDUyWjAZ" + "Agh4AAPpzSk/+hcNMDIwMTAzMTIxMDUyWjAZAghkhx9SFvxAgxcNMDIwMTAzMTIx"
            + "MDUyWjAZAggj4g5SUqaGvBcNMDIwMTAzMTIxMDUyWjAZAghT+nqB0c6vghcNMDIw" + "MTAzMTE1MzMzWjAZAghsBWMAA55+7BcNMDIwMTAzMTE1MzMzWjAZAgg8h0t6rKQY"
            + "ZhcNMDIwMTAzMTE1MzMzWjAZAgh7KFsd40ICwhcNMDIwMTAzMTE1MzM0WjAZAggA" + "kFlDNU8ubxcNMDIwMTAzMTE1MzM0WjAZAghyQfo1XNl0EBcNMDIwMTAzMTE1MzM0"
            + "WjAZAggC5Pz7wI/29hcNMDIwMTAyMTY1NDMzWjAZAggEWvzRRpFGoRcNMDIwMTAy" + "MTY1NDMzWjAZAggC7Q2W0iXswRcNMDIwMTAyMTY1NDMzWjAZAghrfwG3t6vCiBcN"
            + "MDIwMTAyMTY1NDMzWjAZAgg5C+4zxDGEjhcNMDIwMTAyMTY1NDMzWjAZAggX/olM" + "45KxnxcNMDIwMTAyMTY1NDMzWqAvMC0wHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsP"
            + "WFzafOFgLmswCgYDVR0UBAMCAQQwDQYJKoZIhvcNAQEFBQADgYEAPvYDZofCOopw" + "OCKVGaK1aPpHkJmu5Xi1XtRGO9DhmnSZ28hrNu1A5R8OQI43Z7xFx8YK3S56GRuY"
            + "0EGU/RgM3AWhyTAps66tdyipRavKmH6MMrN4ypW/qbhsd4o8JE9pxxn9zsQaNxYZ" + "SNbXM2/YxkdoRSjkrbb9DUdCmCR/kEA=").getBytes());
    private static final byte[] ANY_CRL_BYTES = CRL_BYTES;
    
    private static final Properties GOOD_PROPERTIES;
    
    static {
        GOOD_PROPERTIES = new Properties();
        GOOD_PROPERTIES.setProperty("hostnames", "192.168.10.11");
        GOOD_PROPERTIES.setProperty("port", "567");
        GOOD_PROPERTIES.setProperty("basedn", "dc=test.example.com,dc=com");
        GOOD_PROPERTIES.setProperty("logindn", "cn=Directory Manager");
        GOOD_PROPERTIES.setProperty("loginpassword", "foo123!!");
        GOOD_PROPERTIES.setProperty("usessl", "true");
        GOOD_PROPERTIES.setProperty("logconnectiontests", "true");
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test for initialization and parsing of configuration.
     */
    @Test
    public void testInit() throws Exception {
        final CustomerLdapPublisher1 instance = new CustomerLdapPublisher1();
        
        final String expectedHostnames = "test1.example.com";
        final String expectedPort = "16360";
        final String expectedBaseDN = "dc=test.example,dc=com";
        final String expectedLoginDN = "cn=Directory Manager 1";
        final String expectedLoginPassword = "foo123#123";
        final boolean expectedUseSSL = true;
        final long expectedConnectionTimeout = 5001;
        final long expectedReadTimeout = 30001;
        final long expectedStoreTimeout = 60001;
        final boolean expectedLogConnectionTests = true;
        
        final Properties config = new Properties();
        config.setProperty("hostnames", expectedHostnames);
        config.setProperty("port", expectedPort);
        config.setProperty("basedn", expectedBaseDN);
        config.setProperty("logindn", expectedLoginDN);
        config.setProperty("loginpassword", expectedLoginPassword);
        config.setProperty("usessl", String.valueOf(expectedUseSSL));
        config.setProperty("connectiontimeout", String.valueOf(expectedConnectionTimeout));
        config.setProperty("readtimeout", String.valueOf(expectedReadTimeout));
        config.setProperty("storetimeout", String.valueOf(expectedStoreTimeout));
        config.setProperty("logconnectiontests", String.valueOf(expectedLogConnectionTests));
        
        assertFalse("before inited", instance.isInited());
        instance.init(config);
        assertTrue("after inited", instance.isInited());
        
        assertEquals("hostnames", Arrays.asList(expectedHostnames), instance.getHostnames());
        assertEquals("port", expectedPort, instance.getPort());
        assertEquals("basedn", expectedBaseDN, instance.getBaseDN());
        assertEquals("logindn", expectedLoginDN, instance.getLoginDN());
        assertEquals("loginpassword", expectedLoginPassword, instance.getLoginPassword());
        assertEquals("usessl", expectedUseSSL, instance.isUseSSL());
        assertEquals("timeout", expectedConnectionTimeout, instance.getTimeout());
        assertEquals("connectiontimeout:bind", expectedConnectionTimeout, instance.getLdapBindConstraints().getTimeLimit());
        assertEquals("connectiontimeout:conn", expectedConnectionTimeout, instance.getLdapConnectionConstraints().getTimeLimit());
        assertEquals("connectiontimeout:disconn", expectedConnectionTimeout, instance.getLdapDisconnectConstraints().getTimeLimit());
        assertEquals("readtimeout", expectedReadTimeout, instance.getLdapSearchConstraints().getTimeLimit());
        assertEquals("storetimeout", expectedStoreTimeout, instance.getLdapStoreConstraints().getTimeLimit());
        assertEquals("logconnectiontests", expectedLogConnectionTests, instance.isLogConnectionTests());
    }
    
    /** Tests that storeCertificate can not be called before it has been initialized. */
    @Test
    public void testStoreCertificate_uninitialized() throws Exception {
        try {
            new CustomerLdapPublisher1().storeCertificate(ANY_ADMIN, NULL_CERTIFICATE, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, ANY_TAG, 0, 0, null);
            fail("Expected illegal state as publisher not initialized");
        } catch (IllegalStateException ok) {
            assertEquals("Publisher not initialized", ok.getMessage());
        }
    }
    
    /** Tests the logic in storeCertificate when storing active end entity certificates. */
    @Test
    public void testStoreCertificate_activeEndentity() throws Exception {
        // Create mocked instance
        MockedCustomerLdapPublisher1 instance = new MockedCustomerLdapPublisher1();
        instance.init(GOOD_PROPERTIES);
        
        // Successfull storage and logging of an ACTIVE ENDENTITY certificate
        final Certificate cert = CertTools.getCertfromByteArray(ANY_CERT_BYTES);
        instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, ANY_TAG, 0, 0, null);
        assertTrue("doStoreCertificate called", instance.isDoStoreCertificateCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertTrue("log success", instance.getStoreLogParameters().isSuccess());
        assertEquals("info logging", "info", instance.getStoreLogParameters().getLevel());
        
        // Now similate storage failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoStoreCertificateException(new PublisherException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.init(GOOD_PROPERTIES);
        
        // Failing to store an ACTIVE ENDENTITY certificate
        try {
            instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, ANY_TAG, 0, 0, null);
            fail("Expected publisher exception");
        } catch (PublisherException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doStoreCertificate called", instance.isDoStoreCertificateCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertFalse("log failure", instance.getStoreLogParameters().isSuccess());
        assertEquals("error logging", "err", instance.getStoreLogParameters().getLevel());
        
        // Now similate logging failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setStoreLogException(new PublisherException("SIMULATED_LOG_FAILURE")); // Simulate log failure
        instance.init(GOOD_PROPERTIES);
        
        // Successfull storage but failure to log of an ACTIVE ENDENTITY certificate
        // This should not result in an exception as the certificate was published and should not end up on publish queue
        try {
            instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, ANY_TAG, 0, 0, null);
            assertTrue("doStoreCertificate called", instance.isDoStoreCertificateCalled());
            assertTrue("storeLog called", instance.isStoreLogCalled());
            assertTrue("log success", instance.getStoreLogParameters().isSuccess());
            assertEquals("info logging", "info", instance.getStoreLogParameters().getLevel());
        } catch (PublisherException failure) {
            fail("Should not have thrown exception: " + failure.getMessage());
        }
        
        // Now similate storage AND logging failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoStoreCertificateException(new PublisherException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.setStoreLogException(new PublisherException("SIMULATED_LOG_FAILURE")); // Simulate log failure
        instance.init(GOOD_PROPERTIES);
        
        // Failed storage and failed log of an ACTIVE ENDENTITY certificate
        try {
            instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, ANY_TAG, 0, 0, null);
        } catch (PublisherException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doStoreCertificate called", instance.isDoStoreCertificateCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertFalse("log failure", instance.getStoreLogParameters().isSuccess());
        assertEquals("error logging", "err", instance.getStoreLogParameters().getLevel());
    }
    
    /** Tests the logic in storeCertificate when storing non-active or non end entity certificates. */
    @Test
    public void testStoreCertificate_NonActiveOrNonEndentity() throws Exception {
        // Create mocked instance
        MockedCustomerLdapPublisher1 instance = new MockedCustomerLdapPublisher1();
        instance.init(GOOD_PROPERTIES);
        
        // Should not store ROOT CA certificates
        final Certificate cert = CertTools.getCertfromByteArray(ANY_CERT_BYTES);
        instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ROOTCA, 0, 0, ANY_TAG, 0, 0, null);
        assertFalse("doStoreCertificate called for ROOTCA", instance.isDoStoreCertificateCalled());
        assertFalse("storeLog called for root ca", instance.isStoreLogCalled());
        
        // Should not store SUB CA certificates
        instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_SUBCA, 0, 0, ANY_TAG, 0, 0, null);
        assertFalse("doStoreCertificate called for SUBCA", instance.isDoStoreCertificateCalled());
        assertFalse("storeLog called for sub ca", instance.isStoreLogCalled());
        
        // Should not store non-active certificates (ie. revokations)
        instance.storeCertificate(ANY_ADMIN, cert, ANY_USERNAME, ANY_PASSWORD, ANY_SUBJECTDN, ANY_CAFP, CertificateConstants.CERT_REVOKED, CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, ANY_TAG, 0, 0, null);
        assertFalse("doStoreCertificate called for revokation", instance.isDoStoreCertificateCalled());
        assertFalse("storeLog called for revokation", instance.isStoreLogCalled());
    }
    
    /** Tests that storeCRL can not be called before it has been initialized. */
    @Test
    public void testStoreCRL_uninitialized() throws Exception {
        try {
            new CustomerLdapPublisher1().storeCRL(ANY_ADMIN, ANY_BYTEARRAY, ANY_TAG, ANY_NUMBER, ANY_SUBJECTDN);
            fail("Expected illegal state as publisher not initialized");
        } catch (IllegalStateException ok) {
            assertEquals("Publisher not initialized", ok.getMessage());
        }
    }
    
    /** Tests the logic in storeCRL. */
    @Test
    public void testStoreCRL() throws Exception {
        // Create mocked instance
        MockedCustomerLdapPublisher1 instance = new MockedCustomerLdapPublisher1();
        instance.init(GOOD_PROPERTIES);
        
        // Successfull storage and logging
        instance.storeCRL(ANY_ADMIN, ANY_CRL_BYTES, ANY_CAFP, ANY_NUMBER, ANY_SUBJECTDN);
        assertTrue("doStoreCRL called", instance.isDoStoreCRLCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertTrue("log success", instance.getStoreLogParameters().isSuccess());
        assertEquals("info logging", "info", instance.getStoreLogParameters().getLevel());
        assertTrue("crl bytes", Arrays.equals(ANY_CRL_BYTES, instance.getDoStoreCRLParameters().getIncrl()));
        
        // Now similate storage failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoStoreCRLException(new PublisherException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.init(GOOD_PROPERTIES);
        
        // Failing to store an ACTIVE ENDENTITY certificate
        try {
            instance.storeCRL(ANY_ADMIN, ANY_CRL_BYTES, ANY_CAFP, ANY_NUMBER, ANY_SUBJECTDN);
            fail("Expected publisher exception");
        } catch (PublisherException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doStoreCertificate called", instance.isDoStoreCRLCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertFalse("log failure", instance.getStoreLogParameters().isSuccess());
        assertEquals("error logging", "err", instance.getStoreLogParameters().getLevel());
        
        // Now similate logging failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setStoreLogException(new PublisherException("SIMULATED_LOG_FAILURE")); // Simulate log failure
        instance.init(GOOD_PROPERTIES);
        
        // Successfull storage but failure to log of an ACTIVE ENDENTITY certificate
        // This should not result in an exception as the certificate was published and should not end up on publish queue
        try {
            instance.storeCRL(ANY_ADMIN, ANY_CRL_BYTES, ANY_CAFP, ANY_NUMBER, ANY_SUBJECTDN);
            assertTrue("doStoreCRL called", instance.isDoStoreCRLCalled());
            assertTrue("storeLog called", instance.isStoreLogCalled());
            assertTrue("log success", instance.getStoreLogParameters().isSuccess());
            assertEquals("info logging", "info", instance.getStoreLogParameters().getLevel());
        } catch (PublisherException failure) {
            fail("Should not have thrown exception: " + failure.getMessage());
        }
        
        // Now similate storage AND logging failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoStoreCRLException(new PublisherException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.setStoreLogException(new PublisherException("SIMULATED_LOG_FAILURE")); // Simulate log failure
        instance.init(GOOD_PROPERTIES);
        
        // Failed storage and failed log of an ACTIVE ENDENTITY certificate
        try {
            instance.storeCRL(ANY_ADMIN, ANY_CRL_BYTES, ANY_CAFP, ANY_NUMBER, ANY_SUBJECTDN);
        } catch (PublisherException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doStoreCRL called", instance.isDoStoreCRLCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertFalse("log failure", instance.getStoreLogParameters().isSuccess());
        assertEquals("error logging", "err", instance.getStoreLogParameters().getLevel());
    }
    
    /** Tests that testConnection can not be called before it has been initialized. */
    @Test
    public void testConnection_uninitialized() throws Exception {
        try {
            new CustomerLdapPublisher1().testConnection();
            fail("Expected illegal state as publisher not initialized");
        } catch (IllegalStateException ok) {
            assertEquals("Publisher not initialized", ok.getMessage());
        }
    }
    
    /** Tests the logic in testConnection. */
    @Test
    public void testConnection() throws Exception {
        // Create mocked instance
        MockedCustomerLdapPublisher1 instance = new MockedCustomerLdapPublisher1();
        instance.init(GOOD_PROPERTIES);
        
        // Successfull connection test
        instance.testConnection();
        assertTrue("doTestConnection called", instance.isDoTestConnectionCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertTrue("log success", instance.getStoreLogParameters().isSuccess());
        assertEquals("debug logging", "debug", instance.getStoreLogParameters().getLevel());
        
        // Now similate storage failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoTestConnectionException(new PublisherConnectionException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.init(GOOD_PROPERTIES);
        
        // Failing to test connection
        try {
            instance.testConnection();
            fail("Expected publisher exception");
        } catch (PublisherConnectionException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doTestConnection called", instance.isDoTestConnectionCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertFalse("log failure", instance.getStoreLogParameters().isSuccess());
        assertEquals("error logging", "err", instance.getStoreLogParameters().getLevel());
        
        // Now similate logging failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setStoreLogException(new PublisherException("SIMULATED_LOG_FAILURE")); // Simulate log failure
        instance.init(GOOD_PROPERTIES);
        
        // Successfull connection test but failure to log
        // This should not result in an exception
        try {
            instance.testConnection();
            assertTrue("doTestConnection called", instance.isDoTestConnectionCalled());
            assertTrue("storeLog called", instance.isStoreLogCalled());
            assertTrue("log success", instance.getStoreLogParameters().isSuccess());
            assertEquals("info logging", "debug", instance.getStoreLogParameters().getLevel());
        } catch (PublisherConnectionException failure) {
            fail("Should not have thrown exception: " + failure.getMessage());
        }
        
        // Now similate storage AND logging failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoTestConnectionException(new PublisherConnectionException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.setStoreLogException(new PublisherException("SIMULATED_LOG_FAILURE")); // Simulate log failure
        instance.init(GOOD_PROPERTIES);
        
        // Failed connection test and failed log
        try {
            instance.testConnection();
        } catch (PublisherConnectionException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doTestConnection called", instance.isDoTestConnectionCalled());
        assertTrue("storeLog called", instance.isStoreLogCalled());
        assertFalse("log failure", instance.getStoreLogParameters().isSuccess());
        assertEquals("error logging", "err", instance.getStoreLogParameters().getLevel());
    }
    
    /** Tests the logic in testConnection when logging is disabled. */
    @Test
    public void testConnection_nolog() throws Exception {
        // Create mocked instance
        MockedCustomerLdapPublisher1 instance = new MockedCustomerLdapPublisher1();
        final Properties properties = new Properties(GOOD_PROPERTIES);
        properties.setProperty("logconnectiontests", "false"); // no logging
        instance.init(properties);
        
        // Successfull connection test
        instance.testConnection();
        assertTrue("doTestConnection called", instance.isDoTestConnectionCalled());
        assertFalse("storeLog not called", instance.isStoreLogCalled());
        
        // Now similate storage failure
        instance = new MockedCustomerLdapPublisher1();
        instance.setDoTestConnectionException(new PublisherConnectionException("SIMULATED_STORE_FAILURE")); // Simulate store failure
        instance.init(properties);
        
        // Failing to test connection
        try {
            instance.testConnection();
            fail("Expected publisher exception");
        } catch (PublisherConnectionException ok) {
            assertTrue(ok.getMessage().contains("SIMULATED_STORE_FAILURE"));
        }
        assertTrue("doTestConnection called", instance.isDoTestConnectionCalled());
        assertFalse("storeLog not called", instance.isStoreLogCalled());
    }
    
    /** Tests the logic and implementation details of doStoreCertificate. */
    @Test
    public void testDoStoreCertificate() throws Exception {
        
        final X509Certificate bcCert = (X509Certificate) CertTools.getCertfromByteArray(CERT_BYTES);
        final X509Certificate sunCert = (X509Certificate) CertTools.getCertfromByteArray(CERT_BYTES, "SUN");
        
        // Test storage of an new entry
        SecondMockedCustomerLdapPublisher1 instance = new SecondMockedCustomerLdapPublisher1();
        instance.init(GOOD_PROPERTIES);
        instance.setSearchOldEntityReturn(null); // No old enttry
        
        // Test with BC cert
        instance.doStoreCertificate(bcCert, ANY_USERNAME, ANY_PASSWORD, CERT_ISSUERDN, null);
        assertTrue("serachOldEntity called", instance.isSearchOldEntityCalled());
        assertTrue("writeCertEntryToLDAP called", instance.isWriteCertEntryToLDAPCalled());
        SecondMockedCustomerLdapPublisher1.WriteCertEntryToLDAPParameters params = instance.getWriteCertEntryToLDAPParameters();
        LDAPEntry newEntry = params.getNewEntry();
        
        //newEntry.writeDSML(System.out);
        
        // Note: The DN should be in the reversed order as compared to the certificate according to RFC2253 and the customer/PKD requirements
        assertEquals("ldapDN", "CN=C=SE\\,O=Test\\,CN=Test+sn=20EAA2570247CFEF,ou=staging,dc=test.example.com,dc=com", newEntry.getDN());
        LDAPAttributeSet attributeSet = newEntry.getAttributeSet();
        assertNotNull(attributeSet.getAttribute("sn"));
        assertNotNull(attributeSet.getAttribute("checksum"));
        assertNotNull(attributeSet.getAttribute("objectclass"));

        // Test with Sun cert
        instance.doStoreCertificate(sunCert, ANY_USERNAME, ANY_PASSWORD, CERT_ISSUERDN, null);
        assertTrue("serachOldEntity called", instance.isSearchOldEntityCalled());
        assertTrue("writeCertEntryToLDAP called", instance.isWriteCertEntryToLDAPCalled());
        params = instance.getWriteCertEntryToLDAPParameters();
        newEntry = params.getNewEntry();
        
        //newEntry.writeDSML(System.out);
        
        // Note: The DN should be in the reversed order as compared to the certificate according to RFC2253 and the customer/PKD requirements
        assertEquals("ldapDN", "CN=C=SE\\,O=Test\\,CN=Test+sn=20EAA2570247CFEF,ou=staging,dc=test.example.com,dc=com", newEntry.getDN());
    }
    
    /** Tests the logic and implementation details of doStoreCRL. */
    @Test
    public void testDoStoreCRL() throws Exception {
        // Precondition
        final X509CRL crl = CertTools.getCRLfromByteArray(CRL_BYTES);
        if ("CN=TestCA, O=AnaTom, C=SE".equals(crl.getIssuerDN().getName())) {
            throw new Exception("Test assumes the CRL to have the DN: CN=TestCA, O=AnaTom, C=SE but was: " + crl.getIssuerDN().getName());
        }
        
        // Test storage of an new entry
        SecondMockedCustomerLdapPublisher1 instance = new SecondMockedCustomerLdapPublisher1();
        instance.init(GOOD_PROPERTIES);
        instance.setSearchOldEntityReturn(null); // No old enttry
        
        instance.doStoreCRL(CRL_BYTES);
        assertTrue("serachOldEntity called", instance.isSearchOldEntityCalled());
        assertTrue("writeCrlEntryToLDAP called", instance.isWriteCrlEntryToLDAPCalled());
        SecondMockedCustomerLdapPublisher1.WriteCrlEntryToLDAPParameters params = instance.getWriteCrlEntryToLDAPParameters();
        LDAPEntry newEntry = params.getNewEntry();
        
        //newEntry.writeDSML(System.out);
        
        // Note: The DN should be in the reversed order as compared to the certificate according to RFC2253 and the customer/PKD requirements
        assertEquals("ldapDN", "CN=C=SE\\,O=AnaTom\\,CN=TestCA,ou=staging,dc=test.example.com,dc=com", newEntry.getDN());
        LDAPAttributeSet attributeSet = newEntry.getAttributeSet();
        assertNull(attributeSet.getAttribute("sn"));
        assertNotNull(attributeSet.getAttribute("checksum"));
        assertNotNull(attributeSet.getAttribute("objectclass"));
    }
    
    /** Tests the logic in storeLog. */
    @Test
    public void testStoreLog() throws Exception {
        // Create mocked instance
        ThirdMockedCustomerLdapPublisher1 instance = new ThirdMockedCustomerLdapPublisher1();
        instance.setTime(1378451489999L);
        instance.init(GOOD_PROPERTIES);
        
        // Successfull logging
        instance.storeLog(LogInfo.LEVEL_DEBUG, true, "Testing logging", null);
        assertTrue("writeLog called", instance.isWriteLogEntryToLDAPCalled());
        assertEquals("log DN", "logTime=20130906071129.999Z,cn=log,dc=test.example.com,dc=com", instance.getWriteCertEntryToLDAPParameters().get(0).getNewEntry().getDN());
        
        // Test logging again with same time => should use time +1ms
        instance.clearWriteCertEntryToLDAPParameters();
        
        instance.storeLog(LogInfo.LEVEL_DEBUG, true, "Testing logging 2", null);
        assertTrue("writeLog called", instance.isWriteLogEntryToLDAPCalled());
        // First same DN again
        assertEquals("log DN", "logTime=20130906071129.999Z,cn=log,dc=test.example.com,dc=com", instance.getWriteCertEntryToLDAPParameters().get(0).getNewEntry().getDN());
        
        // Then with logTime +1ms
        assertEquals("two calls", 2, instance.getWriteCertEntryToLDAPParameters().size());
        LDAPEntry newEntry = instance.getWriteCertEntryToLDAPParameters().get(1).getNewEntry();
        String logInfo = newEntry.getAttribute("logInfo").getStringValue();
        assertEquals("log DN", "logTime=20130906071130.000Z,cn=log,dc=test.example.com,dc=com", newEntry.getDN());
        assertTrue("logInfo is " + logInfo, logInfo.contains("time:20130906071129.999Z"));
        
        
        // This time it will now work as there are already entry 0 and 0+1 available
        instance.clearWriteCertEntryToLDAPParameters();
        try {
            instance.storeLog(LogInfo.LEVEL_DEBUG, true, "Testing logging 3", null);
            fail("Should have thrown exception");
        } catch (PublisherException expected) {} // NOPMD
        assertTrue("writeLog called", instance.isWriteLogEntryToLDAPCalled());
        // First same DN again
        assertEquals("log DN", "logTime=20130906071129.999Z,cn=log,dc=test.example.com,dc=com", instance.getWriteCertEntryToLDAPParameters().get(0).getNewEntry().getDN());
        
        // Then with logTime +1ms
        assertEquals("two calls", 2, instance.getWriteCertEntryToLDAPParameters().size());
        assertEquals("log DN", "logTime=20130906071130.000Z,cn=log,dc=test.example.com,dc=com", instance.getWriteCertEntryToLDAPParameters().get(1).getNewEntry().getDN());
        
    }
}
