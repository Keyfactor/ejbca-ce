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
package org.ejbca.scp.publisher;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * 
 * This test provides some simple boilerplate to test an scp to a known server. Tests are set to ignore until somebody figures out how to makes this test 
 * work universally. 
 * 
 * @version $Id$
 *
 */
public class ScpPublisherTest {

    private static final byte[] testCrl = Base64.decode(("MIIBjjB4AgEBMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMMCkx1bmFDQTEwMjQX"
            +"DTEwMTEyNTEwMzkwMFoXDTEwMTEyNjEwMzkwMFqgLzAtMB8GA1UdIwQYMBaAFHxk"
            +"N9a5Vyro6OD5dXiAbqLfxXo3MAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBBQUAA4IB"
            +"AQCoEY8mTbUwFaHLWYNBhh9q07zhj+2UhN2q/JzJppPonkn8qwnFYAc0MXnLV3et"
            +"TE10N40jx+wxhNzerKi5aPP5VugVZVPRCwhH3ObwZpzQToYaa/ypbXp/7Pnz6K2Y"
            +"n4NVbutNKreBRyoXmyuRB5YaiJII1lTHLOu+NCkUTREVCE3xd+OQ258TTW+qgUgy"
            +"u0VnpowMyEwfkxZQkVXI+9woowKvu07DJmG7pNeAZWRT8ff1pzCERB39qUJExVcn"
            +"g9LkoIo1SpZnHh+oELNJA0PrjYdVzerkG9fhtzo54dVDp9teVUHuJOp9NAG9U3XW"
            +"bBc+OH6NrfpkCWsw9WLdrOK2").getBytes());
    
    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    private static final String CA_NAME = "ScpPublisherTest";
    private static final String CA_DN = "CN="+ CA_NAME;
    
    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScpPublisherTest"));
    
    @Before
    public void setup() throws CAExistsException, CryptoTokenOfflineException, AuthorizationDeniedException {
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(internalAdmin, CA_NAME, String.valueOf(1024));
        CAToken caToken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo caInfo = X509CAInfo.getDefaultX509CAInfo(CA_DN, CA_NAME, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d",
                CAInfo.SELFSIGNED, null, caToken);
        final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        try {
            caAdminSession.createCA(internalAdmin, caInfo);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalArgumentException("Could not create CA.", e);
        }
    }
    
    @After
    public void tearDown() throws AuthorizationDeniedException {
        CaTestCase.removeTestCA(CA_NAME);
    }

    @Ignore
    @Test
    public void testPublishCertificate() throws Exception {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo cainfo = caSession.getCAInfo(internalAdmin, CA_NAME);
        CAToken catoken = cainfo.getCAToken();
        catoken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "foo");
        cainfo.setCAToken(catoken);
        caSession.editCA(internalAdmin, cainfo);
        ScpPublisher scpPublisher = new ScpPublisher();
        Properties properties = new Properties();
        properties.setProperty(ScpPublisher.SIGNING_CA_PROPERTY_NAME, Integer.toString(CA_DN.hashCode()));
        properties.setProperty(ScpPublisher.ANONYMIZE_CERTIFICATES_PROPERTY_NAME, "false");
        properties.setProperty(ScpPublisher.CERT_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.CRL_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PROPERTY_NAME, "/Users/mikek/.ssh/id_rsa");
        properties.setProperty(ScpPublisher.SCP_KNOWN_HOSTS_PROPERTY_NAME, "/Users/mikek/.ssh/known_hosts");
        properties.setProperty(ScpPublisher.SSH_USERNAME, "mikek");
        String password = "";
        String encryptionKey = "supersecretpassword";
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PASSWORD_NAME, StringTools.pbeEncryptStringWithSha256Aes192(password, encryptionKey, false));
        scpPublisher.init(properties);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 
        final int reason = RevocationReasons.KEYCOMPROMISE.getDatabaseValue();
        final long date = 1541434399560L;
        final String subjectDn = "C=SE,O=PrimeKey,CN=ScpPublisherTest";
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=PrimeKey,CN=ScpPublisherTest", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);     
        TestAlwaysAllowLocalAuthenticationToken testAlwaysAllowLocalAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken("testPublishCertificate");
        final String username = "ScpContainer";
        final long lastUpdate = 4711L;
        final int certificateProfileId = 1337;
        scpPublisher.storeCertificate(testAlwaysAllowLocalAuthenticationToken, certificate, username, null, subjectDn, null, CertificateConstants.CERT_REVOKED, 
                CertificateConstants.CERTTYPE_ENDENTITY, date, reason, null, certificateProfileId, lastUpdate, null);
        //To check that publisher works, verify that the published certificate exists at the location
    }
    
    @Ignore 
    @Test
    public void testPublishCrl() throws PublisherException {
        ScpPublisher scpPublisher = new ScpPublisher();
        Properties properties = new Properties();
        properties.setProperty(ScpPublisher.ANONYMIZE_CERTIFICATES_PROPERTY_NAME, "false");
        properties.setProperty(ScpPublisher.CERT_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.CRL_SCP_DESTINATION_PROPERTY_NAME, "download.primekey.com:tmp");
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PROPERTY_NAME, "/Users/mikek/.ssh/id_rsa");
        properties.setProperty(ScpPublisher.SCP_KNOWN_HOSTS_PROPERTY_NAME, "/Users/mikek/.ssh/known_hosts");
        properties.setProperty(ScpPublisher.SSH_USERNAME, "mikek");
        String password = "";
        final String encryptionKey = "supersecretpassword";
        properties.setProperty(ScpPublisher.SCP_PRIVATE_KEY_PASSWORD_NAME, StringTools.pbeEncryptStringWithSha256Aes192(password, encryptionKey, false));
        scpPublisher.init(properties);
        TestAlwaysAllowLocalAuthenticationToken testAlwaysAllowLocalAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken("testPublishCrl");
        scpPublisher.storeCRL(testAlwaysAllowLocalAuthenticationToken, testCrl, null, 0, null);
        //To check that publisher works, verify that the published CRL exists at the location
    }

}
