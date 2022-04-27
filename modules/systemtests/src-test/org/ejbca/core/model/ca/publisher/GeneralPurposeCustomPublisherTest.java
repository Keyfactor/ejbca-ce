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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.commons.lang.SystemUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * This is a system test, due to it being OS dependent.
 */
public class GeneralPurposeCustomPublisherTest {
    
    private static final String EXTERNAL_COMMAND_UNIX = "ls";
    private static final String EXTERNAL_COMMAND_WINDOWS = "cmd.exe /c dir";
    private static final String EXTERNAL_COMMAND_UNIX_FAILSAFE = "echo";
    private static final String EXTERNAL_COMMAND_WINDOWS_FAILSAFE = "cmd.exe /c echo";
    private static final String INVALID_OPTION_1 = " --------------:";
    private static final String INVALID_OPTION_2 = " /parameterthatdoesnotexist";

    private static final byte[] TEST_CRL = Base64.decode(("MIIDEzCCAnwCAQEwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UEAxMGVGVzdENBMQ8w"
            + "DQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFFw0wMjAxMDMxMjExMTFaFw0wMjAx" + "MDIxMjExMTFaMIIB5jAZAggfi2rKt4IrZhcNMDIwMTAzMTIxMDUxWjAZAghAxdYk"
            + "7mJxkxcNMDIwMTAzMTIxMDUxWjAZAgg+lCCL+jumXxcNMDIwMTAzMTIxMDUyWjAZ" + "Agh4AAPpzSk/+hcNMDIwMTAzMTIxMDUyWjAZAghkhx9SFvxAgxcNMDIwMTAzMTIx"
            + "MDUyWjAZAggj4g5SUqaGvBcNMDIwMTAzMTIxMDUyWjAZAghT+nqB0c6vghcNMDIw" + "MTAzMTE1MzMzWjAZAghsBWMAA55+7BcNMDIwMTAzMTE1MzMzWjAZAgg8h0t6rKQY"
            + "ZhcNMDIwMTAzMTE1MzMzWjAZAgh7KFsd40ICwhcNMDIwMTAzMTE1MzM0WjAZAggA" + "kFlDNU8ubxcNMDIwMTAzMTE1MzM0WjAZAghyQfo1XNl0EBcNMDIwMTAzMTE1MzM0"
            + "WjAZAggC5Pz7wI/29hcNMDIwMTAyMTY1NDMzWjAZAggEWvzRRpFGoRcNMDIwMTAy" + "MTY1NDMzWjAZAggC7Q2W0iXswRcNMDIwMTAyMTY1NDMzWjAZAghrfwG3t6vCiBcN"
            + "MDIwMTAyMTY1NDMzWjAZAgg5C+4zxDGEjhcNMDIwMTAyMTY1NDMzWjAZAggX/olM" + "45KxnxcNMDIwMTAyMTY1NDMzWqAvMC0wHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsP"
            + "WFzafOFgLmswCgYDVR0UBAMCAQQwDQYJKoZIhvcNAQEFBQADgYEAPvYDZofCOopw" + "OCKVGaK1aPpHkJmu5Xi1XtRGO9DhmnSZ28hrNu1A5R8OQI43Z7xFx8YK3S56GRuY"
            + "0EGU/RgM3AWhyTAps66tdyipRavKmH6MMrN4ypW/qbhsd4o8JE9pxxn9zsQaNxYZ" + "SNbXM2/YxkdoRSjkrbb9DUdCmCR/kEA=").getBytes());

    private static final byte[] TEST_DELTA_CRL = Base64.decode(("MIIBwDCBqQIBATANBgkqhkiG9w0BAQUFADA3MREwDwYDVQQDDAhBZG1pbkNBMTEV"
            + "MBMGA1UECgwMRUpCQ0EgU2FtcGxlMQswCQYDVQQGEwJTRRcNMTAwNjE2MTAxNzQ1" + "WhcNMTAwNjE2MTAxODQ1WqA+MDwwHwYDVR0jBBgwFoAUU9A6yEuUq8oV/pdtlDsY"
            + "qspMSRQwCgYDVR0UBAMCAQIwDQYDVR0bAQH/BAMCAQEwDQYJKoZIhvcNAQEFBQAD" + "ggEBAGvzgVy06ZBUjpUvsUX7XVbnBWRSdZFidhmaitqpMMZHDsOgWHkzzYibFNFO"
            + "9AQrYXMjvUcrN+vR2AaFFwkNM26KcqjLUl28MeMoS4coS/LejzAeuHEg7IQ223Ig" + "H/SlGy/0itplit0QrRP0h6VYvJa4xV9T1lIwunENZ6yv6GZydwmfdfgELzyuUF0R"
            + "mEKtsJS7MiZjcM3JHAzcg35AvPew16yh4IEzEJSvRumgUz+9KMN568VUmRBMsQny" + "DFNrNKoDPLzM28Bqnw7J2+plSuW/bjfytyysSRK7AMjGGgHpfByL2sm10rjNVWyo"
            + "SBLQ/yq6MvqpNaM96U3Uwp0TyMo=").getBytes());

    private AuthenticationToken admin;
    private GeneralPurposeCustomPublisher gpcPublisher;
    private String command;
    private String invalidOption;
    private String commandFailsafe;
 
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setUp() throws IOException, InterruptedException {
        admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("GenPurpCustomePublisherTest"));
        gpcPublisher = new GeneralPurposeCustomPublisher();
        // Make sure an external command exists for testing purposes
        if (SystemUtils.IS_OS_WINDOWS) {
            command = EXTERNAL_COMMAND_WINDOWS;
            commandFailsafe = EXTERNAL_COMMAND_WINDOWS_FAILSAFE;
            invalidOption = INVALID_OPTION_2;
        } else {
            command = EXTERNAL_COMMAND_UNIX;
            commandFailsafe = EXTERNAL_COMMAND_UNIX_FAILSAFE;
            invalidOption = INVALID_OPTION_1;
        }
        assertNotNull("This test requires \"" + EXTERNAL_COMMAND_UNIX + "\" or \"" + EXTERNAL_COMMAND_WINDOWS + "\"to be available.", command);
    }

    @After
    public void tearDown() {
        admin = null;
        gpcPublisher = null;
    }
    
    /**
     * Test normal operation of GeneralPurposeCustomPublisher.
     *            
     */
    @Test
    public void testStoreCRL() {
        Properties props = new Properties();

        // Test function by calling a command that is available on most
        // platforms
        boolean ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, command);
            gpcPublisher.init(props);
            gpcPublisher.setExternalScriptsAllowlist(ExternalScriptsAllowlist.permitAll());
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
            e.printStackTrace();
        }
        assertTrue("Store CRL with GeneralPurposeCustomPublisher failed.", ret);
    }
    
    /**
     * Tests storing a certificate using arguments passed to the command. 
     */
    @Test
    public void  testStoreCertificateWithArguments() throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException, PublisherException {
        Properties props = new Properties();
        // Test function by calling a command that is available on most platforms
        boolean ret = false;
        props.setProperty(GeneralPurposeCustomPublisher.CERT_EXTERNAL_COMMAND_PROPERTY_NAME, commandFailsafe);
        gpcPublisher.init(props);
        gpcPublisher.setExternalScriptsAllowlist(ExternalScriptsAllowlist.permitAll());
        KeyPair keys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        String certificateDn = "CN=Foo Bar, OU=Xyz Abc";
        X509Certificate cert = CertTools.genSelfCert(certificateDn, 10L, "1.1.1.1", keys.getPrivate(), keys.getPublic(), "SHA256WithECDSA", true);

        ret = gpcPublisher.storeCertificate(admin, cert, "foo", "foo123", certificateDn, "foo", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ENDENTITY, 0, 0, null, 0, 0, null);

        assertTrue("Store Certificate with GeneralPurposeCustomPublisher failed.", ret);
    }

    @Test
    public void testStoreCRLwithDeltaCrl() {
        Properties props = new Properties();
        props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, commandFailsafe);
        props.setProperty(GeneralPurposeCustomPublisher.CALCULATE_DELTA_CRL_LOCALLY_PROPERTY_NAME, "true");
        gpcPublisher.init(props);
        gpcPublisher.setExternalScriptsAllowlist(ExternalScriptsAllowlist.permitAll());
        boolean ret = false;
        try {
            ret = gpcPublisher.storeCRL(admin, TEST_DELTA_CRL, null, 1, null);
        } catch (PublisherException e) {
            fail(e.getLocalizedMessage());
        }
        assertTrue("Publishing a standard CRL with delta check set true failed.", ret);
    }

    @Test
    public void testStoreCRLwithoutDeltaCrl() {
        Properties props = new Properties();
        props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, commandFailsafe);
        props.setProperty(GeneralPurposeCustomPublisher.CALCULATE_DELTA_CRL_LOCALLY_PROPERTY_NAME, "true");
        gpcPublisher.init(props);
        gpcPublisher.setExternalScriptsAllowlist(ExternalScriptsAllowlist.permitAll());
        boolean ret = false;
        try {
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
            fail(e.getLocalizedMessage());
        }
        assertTrue("Publishing a standard CRL with delta check set true failed.", ret);
    }

    @Test
    public void testStoreCRLWithInvalidProperties() {
        Properties props = new Properties();

        // Make sure it fails without a given external command
        boolean ret = false;
        props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, "");
        gpcPublisher.init(props);
        try {
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Store CRL with GeneralPurposeCustomPublisher did not failed with invalid properties.", ret);
    }

    /**
     * Verify that GeneralPurposeCustomPublisher will fail on an error code from
     * an external application.
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void testErrorCodes() {
        Properties props = new Properties();

        // Test function by calling a command that is available on most
        // platforms with invalid option
        boolean ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, command + invalidOption);
            props.setProperty(GeneralPurposeCustomPublisher.CRL_FAIL_ON_ERRORCODE_PROPERTY_NAME, "true");
            props.setProperty(GeneralPurposeCustomPublisher.CRL_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "false");
            gpcPublisher.init(props);
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Store CRL with GeneralPurposeCustomPublisher did not fail on errorcode.", ret);
        ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CERT_EXTERNAL_COMMAND_PROPERTY_NAME, command + invalidOption);
            props.setProperty(GeneralPurposeCustomPublisher.CERT_FAIL_ON_ERRORCODE_PROPERTY_NAME, "true");
            props.setProperty(GeneralPurposeCustomPublisher.CERT_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "false");
            gpcPublisher.init(props);
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Store cert with GeneralPurposeCustomPublisher did not fail on errorcode.", ret);
        ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME, command + invalidOption);
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_FAIL_ON_ERRORCODE_PROPERTY_NAME, "true");
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "false");
            gpcPublisher.init(props);
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Revoke cert with GeneralPurposeCustomPublisher did not fail on errorcode.", ret);
    }

    /**
     * Verify that GeneralPurposeCustomPublisher will fail on output to standard
     * error from an external application.
     * 
     * @throws Exception
     *             error
     */
    @Test
    public void testStandardErrors() {
        Properties props = new Properties();

        // Test function by calling a command that is available on most
        // platforms with invalid option
        boolean ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, command + invalidOption);
            props.setProperty(GeneralPurposeCustomPublisher.CRL_FAIL_ON_ERRORCODE_PROPERTY_NAME, "false");
            props.setProperty(GeneralPurposeCustomPublisher.CRL_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "true");
            gpcPublisher.init(props);
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Store CRL with GeneralPurposeCustomPublisher did not fail on standard error.", ret);
        ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CERT_EXTERNAL_COMMAND_PROPERTY_NAME, command + invalidOption);
            props.setProperty(GeneralPurposeCustomPublisher.CERT_FAIL_ON_ERRORCODE_PROPERTY_NAME, "false");
            props.setProperty(GeneralPurposeCustomPublisher.CERT_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "true");
            gpcPublisher.init(props);
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Store cert with GeneralPurposeCustomPublisher did not fail on standard error.", ret);
        ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME, command + invalidOption);
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_FAIL_ON_ERRORCODE_PROPERTY_NAME, "false");
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "true");
            gpcPublisher.init(props);
            ret = gpcPublisher.storeCRL(admin, TEST_CRL, null, 1, null);
        } catch (PublisherException e) {
        }
        assertFalse("Revoke cert with GeneralPurposeCustomPublisher did not fail on standard error.", ret);
    }

    /**
     * Test that the GeneralPurposeCustomPublisher fails when the external
     * executable file does not exist.
     * 
     * @throws Exception
     */
    @Test
    public void testExternalExecutableDoesNotExist() throws Exception {
        Properties props = new Properties();

        // Test connection separately for all publishers with invalid filename
        boolean ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME, "randomfilenamethatdoesnotexistandneverwill8998752");
            gpcPublisher.init(props);
            gpcPublisher.testConnection();
            ret = true;
        } catch (PublisherConnectionException e) {
        }
        assertFalse("testConnection reported all ok, but commandfile does not exist!", ret);
        ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.CERT_EXTERNAL_COMMAND_PROPERTY_NAME, "randomfilenamethatdoesnotexistandneverwill8998752");
            gpcPublisher.init(props);
            gpcPublisher.testConnection();
            ret = true;
        } catch (PublisherConnectionException e) {
        }
        assertFalse("testConnection reported all ok, but commandfile does not exist!", ret);
        ret = false;
        try {
            props.setProperty(GeneralPurposeCustomPublisher.REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME, "randomfilenamethatdoesnotexistandneverwill8998752");
            gpcPublisher.init(props);
            gpcPublisher.testConnection();
            ret = true;
        } catch (PublisherConnectionException e) {
        }
        assertFalse("testConnection reported all ok, but commandfile does not exist!", ret);
    }
}
