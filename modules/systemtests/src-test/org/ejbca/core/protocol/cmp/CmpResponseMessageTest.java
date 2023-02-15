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
package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.junit.util.CryptoTokenRunner;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

/**
 * This class tests attributes of the CMP response message such as the CA 
 * certificate(s) returned in the caPubs field. 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)
public class CmpResponseMessageTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CmpResponseMessageTest.class);

    @Parameters(name = "{0}")
    public static Collection<CryptoTokenRunner> runners() {
       return CryptoTokenRunner.defaultRunners;
    }
    
    private static final String user = "CmpTestUser";
    private static final String userPwd = "foo123";
    
    private X509Certificate caCertificate;
    private X509CAInfo ca;
    private CmpConfiguration cmpConfiguration;
    private static final String cmpAlias = "CmpResponseMessageTestConfAlias";
    
    private final byte[] nonce = CmpMessageHelper.createSenderNonce();
    private final byte[] transid = CmpMessageHelper.createSenderNonce();

    private String userDnString;
    private X500Name userDn;
    
    private KeyPair keys;
    private PKIMessage msg; 
    private PKIMessage req;
    
    private ByteArrayOutputStream bao;
    private ASN1OutputStream out;
    
    private final String tlsRootCaDN = "CN=Tls-Root-CA";
    private final String tlsSubCaDN = "CN=Tls-Sub-CA";
    private X509CA tls509RootCa;
    private X509CA tls509SubCa;
    
    private CryptoTokenRunner cryptoTokenRunner;
    
    @Rule
    public TestName testName = new TestName();
    
    public CmpResponseMessageTest(CryptoTokenRunner cryptoTokenRunner) throws Exception {
        this.cryptoTokenRunner = cryptoTokenRunner;
        
    }

     
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }
    
    @Rule
    public final TestWatcher traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            log.trace(">" + description.getMethodName());
            super.starting(description);
        };
        @Override
        protected void finished(final Description description) {
            log.trace("<" + description.getMethodName());
            super.finished(description);
        }
    };

    @Before
    public void setUp() throws Exception {
        super.setUp();

        ca = cryptoTokenRunner.createX509Ca("CN="+testName.getMethodName(), testName.getMethodName()); 
        caCertificate = (X509Certificate) ca.getCertificateChain().get(0);
        cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        
        log.debug("Test CA subject DN: " + ca.getSubjectDN());
        log.debug("Test CA ID: " + ca.getCAId());
        
        
        this.cmpConfiguration.addAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        if (endEntityManagementSession.existsUser(user)) {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, user, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }
        
        userDnString = "C=SE,O=PrimeKey Solutions AB,CN=" + user + "-" + System.currentTimeMillis();
        userDn = new X500Name(userDnString);
        createUser(user, userDnString, userPwd, ca.getCAId());
        
        keys = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        msg = genCertReq(ca.getSubjectDN(), userDn, keys, caCertificate, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull("Generating CrmfRequest failed.", msg);
        
        // Using the CMP RA Authentication secret 
        req = protectPKIMessage(msg, false, "foo123", "mykeyid", 567);
        assertNotNull("Protecting PKIMessage with HMACPbe failed.", req);
        
        // The CMP message byte out stream to be send to the CA.
        bao = new ByteArrayOutputStream();
        out = ASN1OutputStream.create(bao, ASN1Encoding.DER);
        out.writeObject(req);
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        cryptoTokenRunner.cleanUp();
        this.cmpConfiguration.removeAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        if (endEntityManagementSession.existsUser(user)) {
            endEntityManagementSession.revokeAndDeleteUser(ADMIN, user, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        }
    }
    
    @Override
    public String getRoleName() {
        return getClass().getSimpleName();
    }
    
    @Test
    public void test01EmptyCaPubsField() throws Exception {
        // Configure empty caPubs field.
        this.cmpConfiguration.setResponseCaPubsCA(cmpAlias, "");
        this.cmpConfiguration.setResponseCaPubsIssuingCA(cmpAlias, false);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        // Send request and receive response.
        final byte[] resp = sendCmpHttp(bao.toByteArray(), 200, cmpAlias);
        
        final List<X509Certificate> caPubs = caPubsCertificatesFromCmpResponse(resp);
        assertNull("CMP response caPubs field must be null if no CA certificates are included in the CMP response.", caPubs);
    }
    
    @Test
    public void test02CaCertificateInCaPubsField() throws Exception {
        // Configure issuing CA certificate at index 0 -> Default setting.
        this.cmpConfiguration.setResponseCaPubsCA(cmpAlias, "");
        this.cmpConfiguration.setResponseCaPubsIssuingCA(cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        // Send request and receive response.
        final byte[] resp = sendCmpHttp(bao.toByteArray(), 200, cmpAlias);

        final List<X509Certificate> caPubs = caPubsCertificatesFromCmpResponse(resp);
        assertNotNull("CMP response caPubs field is null.", caPubs);
        assertEquals("CMP response caPubs number of certificates does not match.", 1, caPubs.size());
        assertArrayEquals("CMP response caPubs certificates does not match.", new X509Certificate[] { caCertificate }, caPubs.toArray(new X509Certificate[] {}));
    }
    
    @Test
    public void test03TwiceCaCertificateInCaPubsField() throws Exception {
        // Configure issuing CA certificate at index 0 -> Default setting
        // AND add a duplicate from the CA list -> duplicate is removed. 
        this.cmpConfiguration.setResponseCaPubsCA(cmpAlias, Integer.toString(ca.getCAId()));
        this.cmpConfiguration.setResponseCaPubsIssuingCA(cmpAlias, true);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        // Send request and receive response.
        final byte[] resp = sendCmpHttp(bao.toByteArray(), 200, cmpAlias);
        
        final List<X509Certificate> caPubs = caPubsCertificatesFromCmpResponse(resp);
        assertNotNull("CMP response caPubs field is null.", caPubs);
        assertEquals("CMP response caPubs number of certificates does not match.", 1, caPubs.size());
        assertArrayEquals("CMP response caPubs certificates does not match.", new X509Certificate[] { caCertificate }, caPubs.toArray(new X509Certificate[] {}));
    }
    
    @Test
    public void test04AdditionalCertificatesInCaPubsField() throws Exception {
        tls509RootCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(ADMIN, this.tlsRootCaDN);
        log.info("Created TLS root CA: " + this.tls509RootCa.getCAToken().getCryptoTokenId());
        log.info("Created TLS root CA certificate chain: " + tls509RootCa.getCertificateChain());
        
        tls509SubCa = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(ADMIN, this.tlsSubCaDN, this.tls509RootCa.getCAId());
        log.info("Created TLS sub CA: " + this.tls509SubCa.getCAToken());
        log.info("Created TLS sub CA certificate chain: " + tls509SubCa.getCertificateChain());
        
        // Configure no issuing CA certificate at index 0 AND add some additional CA certificates including the issuing CA as last.
        this.cmpConfiguration.setResponseCaPubsCA(cmpAlias, Integer.toString(tls509SubCa.getCAId()) 
                + ";" + Integer.toString(tls509RootCa.getCAId()) + ";" + Integer.toString(ca.getCAId()));
        this.cmpConfiguration.setResponseCaPubsIssuingCA(cmpAlias, false); // Default setting.
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        // Send request and receive response.
        final byte[] resp = sendCmpHttp(bao.toByteArray(), 200, cmpAlias);

        final List<X509Certificate> caPubs = caPubsCertificatesFromCmpResponse(resp);
        assertNotNull("CMP response caPubs field is null.", caPubs);
        assertEquals("CMP response caPubs number of certificates does not match.", 3, caPubs.size());
        assertEquals("CMP response caPubs certificate at index 0 does not match.", tls509SubCa.getCACertificate(), caPubs.get(0));
        assertEquals("CMP response caPubs certificate at index 1 does not match.", tls509RootCa.getCACertificate(), caPubs.get(1));
        assertEquals("CMP response caPubs certificate at index 2 does not match.", caCertificate, caPubs.get(2));
        
        removeCAs(new CA[] { tls509SubCa, tls509RootCa });
    }
    
}
