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
package org.ejbca.core.model.ca.publisher;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.cert.Certificate;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Test case for the CertificateSamplerCustomPublisher.
 * 
 * This is a unit test and does not require EJBCA to be running.
 *
 * @version $Id$
 */
public class CertificateSamplerCustomPublisherUnitTest {

    private static final File TEMP_DIR = new File(System.getProperty("java.io.tmpdir"));
    private static final AuthenticationToken ANY_ADMIN = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateSamplerCustomPublisherUnitTest"));
    private static final byte[] ANY_BYTEARRAY = new byte[0];
    private static final String ANY_CAFP = "44447777111";
    private static final int ANY_NUMBER = 4711;
    private static final String ANY_SUBJECTDN = "CN=User";
    private static final Certificate NULL_CERTIFICATE = null;
    private static final int ANY_PROFILEID = 123123;
    private static final int PROBABILISTIC_TRIES = 100;
    
    private static final int PROFILE_A = 10;
    private static final int PROFILE_B = 11;
    
    
    private static final Properties CONFIG_SAMPLE_ALL;
    private static final Properties ANY_GOOD_PROPERTIES;
    
    static {
        CONFIG_SAMPLE_ALL = new Properties();
        CONFIG_SAMPLE_ALL.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        CONFIG_SAMPLE_ALL.setProperty("default.samplingmethod", "SAMPLE_ALL");
        ANY_GOOD_PROPERTIES = CONFIG_SAMPLE_ALL;
    }
    
    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }
    
    /** 
     * Tests that storeCertificate and testConnection throws Exception as the property output folder is missing.  
     */ 
    @Test
	public void testNoOutputFolder() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config = new Properties();
        
        config.setProperty("default.samplingmethod", "SAMPLE_ALL");
        
        // Test storeCertificate
        publisher = createMockedPublisher(config);
        try {
            storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            fail("Should have failed as property outputfolder was missing");
        } catch (PublisherException expected) {} // NOPMD
        
        // Test testConnection
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as property outputfolder was missing");
        } catch (PublisherConnectionException expected) {} // NOPMD
    }
    
    /** 
     * Tests that storeCertificate and testConnection throws Exception as the property for the default sampling method is missing.  
     */ 
    @Test
	public void testNoDefaultSamplingMethod() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config = new Properties();
        
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        
        // Test storeCertificate
        publisher = createMockedPublisher(config);
        try {
            storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            fail("Should have failed as property outputfolder was missing");
        } catch (PublisherException expected) {} // NOPMD
        
        // Test testConnection
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as property outputfolder was missing");
        } catch (PublisherConnectionException expected) {} // NOPMD
    }
    
    /** 
     * Tests that storeCertificate and testConnection throws Exception as the default pvalue is missing.  
     */ 
    @Test
	public void testNoPValueForDefaultSamplingMethod() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config = new Properties();
        
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        
        // Test storeCertificate
        publisher = createMockedPublisher(config);
        try {
            storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            fail("Should have failed as no default pvalue was specified");
        } catch (PublisherException expected) {} // NOPMD
        
        // Test testConnection
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as no default pvalue was specified");
        } catch (PublisherConnectionException expected) {} // NOPMD
    }
    
    /** 
     * Tests that storeCertificate and testConnection throws Exception as the pvalue for a profile is missing.  
     */ 
    @Test
	public void testNoPValueForProfileSamplingMethod() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config = new Properties();
        
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_ALL");
        config.setProperty("profileid." + PROFILE_A + ".samplingmethod", "SAMPLE_PROBABILISTIC");
        
        // Test storeCertificate
        publisher = createMockedPublisher(config);
        try {
            storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A);
            fail("Should have failed as no default pvalue for profile A specified");
        } catch (PublisherException expected) {} // NOPMD
        
        // Test testConnection
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as no pvalue for a profile specified");
        } catch (PublisherConnectionException expected) {} // NOPMD
    }
    
    /**
     * Tests that testConnection gives error if pvalue is invalid.
     */
    @Test
	public void testPvalueNotInInterval() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config;
        
        // Profile pvalue=-0.5 (illegal)
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_ALL");
        config.setProperty("profileid." + PROFILE_A + ".samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("profileid." + PROFILE_A + ".pvalue", "-0.5");
        
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as pvalue is not in the [0, 1] range");
        } catch (PublisherConnectionException expected) {} // NOPMD
        
        // Default pvalue=-0.5 (illegal)
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("default.pvalue", "-0.5");
        
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as pvalue is not in the [0, 1] range");
        } catch (PublisherConnectionException expected) {} // NOPMD
    }
    
    /**
     * Tests that testConnection gives error if there is an invalid profile key.
     */
    @Test
	public void testInvalidProfileKey() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config;
        
        // Profile pvalue=-0.5 (illegal)
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_ALL");
        config.setProperty("profileid.INVALID.samplingmethod", "SAMPLE_ALL");
        
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as 'INVALID' is not an legal profile id");
        } catch (PublisherConnectionException expected) {} // NOPMD
    }
    
    /**
     * Tests that testConnection and storeCertificate gives error if there is an invalid sampling method.
     */
    @Test
	public void testInvalidSamplingMethod() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config;
        
        // Default sampling method: INVALID
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "_INVALID_");
        
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as '_INVALID_' is not an existing sampling method");
        } catch (PublisherConnectionException expected) {} // NOPMD
        publisher = createMockedPublisher(config);
        try {
            storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            fail("Should have failed as '_INVALID_' is not an existing sampling method");
        } catch (PublisherException expected) {} // NOPMD
        
        // Profile sampling method: INVALID
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_ALL");
        config.setProperty("profileid." + PROFILE_A + ".samplingmethod", "_INVALID_");
        
        publisher = createMockedPublisher(config);
        try {
            publisher.testConnection();
            fail("Should have failed as '_INVALID_' is not an existing sampling method");
        } catch (PublisherConnectionException expected) {} // NOPMD
        publisher = createMockedPublisher(config);
        try {
            storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A);
            fail("Should have failed as '_INVALID_' is not an existing sampling method");
        } catch (PublisherException expected) {} // NOPMD
    }
    
    /**
     * Tests that the method storeCRL always returns true as publishing/sampling of CRLs are currently not supported.
     */
    @Test
	public void testStoreCRL() throws Exception {
        assertTrue("Storing CRL is not supported but return status should be success", 
                createPublisher(ANY_GOOD_PROPERTIES).storeCRL(ANY_ADMIN, ANY_BYTEARRAY, ANY_CAFP, ANY_NUMBER, ANY_SUBJECTDN));
    }
    
    /**
     * Tests that revoking a certificate does not invoke any sampling.
     */
    @Test
	public void testStoreCertificateRevoked() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        boolean success;
        
        publisher = createMockedPublisher(ANY_GOOD_PROPERTIES);
        success = storeCertificate(publisher, CertificateConstants.CERT_REVOKED, ANY_PROFILEID);
        assertTrue("Status should be success", success);
        assertFalse("Certificate should not have been stored", publisher.isWriteCertificateCalled());
        
        publisher = createMockedPublisher(ANY_GOOD_PROPERTIES);
        success = storeCertificate(publisher, CertificateConstants.CERT_INACTIVE, ANY_PROFILEID);
        assertTrue("Status should be success", success);
        assertFalse("Certificate should not have been stored", publisher.isWriteCertificateCalled());
    }
    
    /** 
     * Tests that publishing with sampling method ALL stores the certificate.
     */
    @Test
	public void testSampleAll() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        boolean success;
        
        publisher = createMockedPublisher(CONFIG_SAMPLE_ALL);
        success = storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
        assertTrue("Status should be success", success);
        assertTrue("Certificate should have been stored", publisher.isWriteCertificateCalled());
    }
    
    /**
     * Tests sampling with different probabilities. This method has a change of false positives but with
     * <code>PROBABILISTIC_TRIES</code> number of tries the probability should be small.
     */
    @Test
	public void testSampleProbabilistic() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        boolean success;
        
        // Test that with p=0.0 no certificate is stored
        Properties default0 = new Properties();
        default0.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        default0.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        default0.setProperty("default.pvalue", "0.0");
        for (int i = 0; i < PROBABILISTIC_TRIES; i++) {
            publisher = createMockedPublisher(default0);
            success = storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            assertTrue("Status should be success", success);
            assertFalse("Certificate should not have been stored, i=" + i, publisher.isWriteCertificateCalled());
        }
        
        // Test that with pvalue=1.0 all certificates are stored
        Properties default1 = new Properties();
        default1.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        default1.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        default1.setProperty("default.pvalue", "1.0");
        for (int i = 0; i < PROBABILISTIC_TRIES; i++) {
            publisher = createMockedPublisher(default1);
            success = storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            assertTrue("Status should be success", success);
            assertTrue("Certificate should have been stored, i=" + i, publisher.isWriteCertificateCalled());
            publisher.reset();
        }
        
        // Test that with pvalue=0.5 at least some certificates are stored
        Properties default05 = new Properties();
        default05.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        default05.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        default05.setProperty("default.pvalue", "0.5");
        int stored = 0;
        for (int i = 0; i < PROBABILISTIC_TRIES; i++) {
            publisher = createMockedPublisher(default05);
            success = storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID);
            assertTrue("Status should be success", success);
            
            if (publisher.isWriteCertificateCalled()) {
                stored++;
            }
            publisher.reset();
        }
        assertTrue("At least some should have been stored", stored > 0);
    }
    
    /**
     * Tests that different profiles can have different values for pvalue.
     */
    @Test
	public void testDifferentProfiles() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config;
        
        // Default: p=1.0, A: p=0.0, B: p=1.0 
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("default.pvalue", "1.0");
        config.setProperty("profileid." + PROFILE_A + ".pvalue", "0.0");
        config.setProperty("profileid." + PROFILE_B + ".pvalue", "1.0");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertFalse("Certificate in profile A should not be stored", publisher.isWriteCertificateCalled());
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_B));
        assertTrue("Certificate in profile B should have been stored", publisher.isWriteCertificateCalled());
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID));
        assertTrue("Certificate in any other profile should have been stored", publisher.isWriteCertificateCalled());
    }
    
    /**
     * Tests that different profiles can have different sampling methods.
     */
    @Test
	public void testDifferentMethodsForProfiles() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config;
        
        // Default: p=0.0
        // Nothing should be stored
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("default.pvalue", "0.0");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertFalse("Certificate in profile A should not be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_B));
        assertFalse("Certificate in profile B should not be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID));
        assertFalse("Certificate in no profile should not be stored", publisher.isWriteCertificateCalled());
        
        // Default: p=0.0, A: ALL
        // Only from profile A should be stored
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("default.pvalue", "0.0");
        config.setProperty("profileid." + PROFILE_A + ".samplingmethod", "SAMPLE_ALL");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertTrue("Certificate in profile A should be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertTrue("Certificate in profile A should be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_B));
        assertFalse("Certificate in profile B should not be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID));
        assertFalse("Certificate in other profile should not be stored", publisher.isWriteCertificateCalled());
        
        // Default: p=0.0, A: ALL, B: p=1.0
        // Only certificates from profiles A and B should be stored
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("default.pvalue", "0.0");
        config.setProperty("profileid." + PROFILE_A + ".samplingmethod", "SAMPLE_ALL");
        config.setProperty("profileid." + PROFILE_B + ".samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("profileid." + PROFILE_B + ".pvalue", "1.0");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertTrue("Certificate in profile A should be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertTrue("Certificate in profile A should be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_B));
        assertTrue("Certificate in profile B should be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID));
        assertFalse("Certificate in other profile should not be stored", publisher.isWriteCertificateCalled());
    }
    
    /**
     * Tests the NONE sample method.
     */
    @Test
	public void testSampleNone() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config;
        
        // Default: NONE
        // Nothing should be stored
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_NONE");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID));
        assertFalse("Certificate in no profile should not be stored", publisher.isWriteCertificateCalled());
        
        // Default: ALL, A: NONE
        // Only from profile A should be stored
        config = new Properties();
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_ALL");
        config.setProperty("profileid." + PROFILE_A + ".samplingmethod", "SAMPLE_NONE");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertFalse("Certificate in profile A should not be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, ANY_PROFILEID));
        assertTrue("Certificate in other profile should be stored", publisher.isWriteCertificateCalled());
    }
    
    /**
     * Tests that a profile can have a different pvalue than the default but the same method will be used.
     */
    @Test
	public void testDifferentPvalues() throws Exception {
        MockedCertificateSamplerCustomPublisher publisher;
        Properties config = new Properties();
        
        // Default: probabilistic(0.0), profile b: (1.0)
        config.setProperty("outputfolder", TEMP_DIR.getAbsolutePath());
        config.setProperty("default.samplingmethod", "SAMPLE_PROBABILISTIC");
        config.setProperty("default.pvalue", "0.0");
        config.setProperty("profileid." + PROFILE_B + ".pvalue", "1.0");
        
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_A));
        assertFalse("Certificate in profile A should not be stored", publisher.isWriteCertificateCalled());
        publisher = createMockedPublisher(config);
        assertTrue(storeCertificate(publisher, CertificateConstants.CERT_ACTIVE, PROFILE_B));
        assertTrue("Certificate in profile B should be stored", publisher.isWriteCertificateCalled());
    }
    
    /** storeCertificate wrapper. */
    private boolean storeCertificate(ICustomPublisher publisher, int status, int profileId) throws PublisherException {
        return publisher.storeCertificate(ANY_ADMIN, NULL_CERTIFICATE, null, null, null, null, 
                status, 
                0, System.currentTimeMillis(), 0, null, profileId, System.currentTimeMillis(), null);
    }
    
    /** Create publisher wrapper. */
    private CertificateSamplerCustomPublisher createPublisher(Properties properties) {
        CertificateSamplerCustomPublisher result = new CertificateSamplerCustomPublisher();
        result.init(properties);
        return result;
    }
    
    /** Create mocked publisher wrapper. */
    private MockedCertificateSamplerCustomPublisher createMockedPublisher(Properties properties) {
        MockedCertificateSamplerCustomPublisher result = new MockedCertificateSamplerCustomPublisher();
        result.init(properties);
        return result;
    }    
}
