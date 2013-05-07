/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.keybind.InternalKeyBinding;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingStatus;
import org.ejbca.core.ejb.keybind.impl.AuthenticationKeyBinding;
import org.ejbca.core.ejb.keybind.impl.OcspKeyBinding;
import org.ejbca.core.protocol.ocsp.standalone.OcspKeyRenewalProxySessionRemote;
import org.ejbca.util.TraceLogMethodsRule;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * @version $Id$
 *
 */
public class OcspKeyRenewalTest {

    private static final String CA_DN = "CN=OcspDefaultTestCA";
    private static final String TESTCLASSNAME = OcspKeyRenewalTest.class.getSimpleName();
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
    private static final Logger log = Logger.getLogger(OcspKeyRenewalTest.class);

    private static CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private OcspKeyRenewalProxySessionRemote ocspKeyRenewalProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspKeyRenewalProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private OcspResponseGeneratorTestSessionRemote standaloneOcspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
        .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);       
    private static final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);       
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private static X509CA x509ca;
    private static int cryptoTokenId;
    private static int ocspKeyBindingId;
    private static X509Certificate ocspSigningCertificate;
    private static X509Certificate caCertificate;
    private static int authenticationKeyBindingId;
    private static X509Certificate clientSSLCertificate;
    private static int managementCaId = 0;

    @BeforeClass
    public static void beforeClass() throws Exception {
        x509ca = CryptoTokenTestUtils.createTestCA(authenticationToken, CA_DN);
        log.debug("OCSP CA Id: " + x509ca.getCAId() + " CA SubjectDN: " + x509ca.getSubjectDN());
        cryptoTokenId = CryptoTokenTestUtils.createCryptoToken(authenticationToken, TESTCLASSNAME);
        ocspKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASSNAME + "-ocsp");
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, ocspKeyBindingId, x509ca.getCAId());
        OcspTestUtils.updateInternalKeyBindingCertificate(authenticationToken, ocspKeyBindingId);
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, ocspKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        caCertificate = ProtocolOcspHttpStandaloneTest.createCaCertificate(authenticationToken, x509ca.getCACertificate());
        // Ensure that the new ocsp signing certificate is picked up by the cache
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // Reuse the same CryptoToken for the client SSL authentication
        authenticationKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, AuthenticationKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASSNAME + "-ssl");
        // We need to issue the SSL certificate from an issuer trusted by the server (AdminCA1/ManagementCA)
        try {
            managementCaId = caSession.getCAInfo(authenticationToken, "AdminCA1").getCAId();
        } catch (CADoesntExistsException e) {
            try {
                managementCaId = caSession.getCAInfo(authenticationToken, "ManagementCA").getCAId();
            } catch (CADoesntExistsException e2) {
                // Test relying on SSL will fail
            }
        }
        log.debug("SSL CA Id: " + managementCaId);
        if (managementCaId != 0) {
            clientSSLCertificate = OcspTestUtils.createClientSSLCertificate(authenticationToken, authenticationKeyBindingId, managementCaId);
            OcspTestUtils.updateInternalKeyBindingCertificate(authenticationToken, authenticationKeyBindingId);
            OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, authenticationKeyBindingId, InternalKeyBindingStatus.ACTIVE);
            // Add authorization rules for this client SSL certificate
            final RoleInitializationSessionRemote roleInitSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
            roleInitSession.initializeAccessWithCert(authenticationToken, TESTCLASSNAME, clientSSLCertificate);
        }
        // Set re-keying URL to our local instance
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.REKEYING_WSURL, "https://localhost:8443/ejbca/ejbcaws/ejbcaws");
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        roleManagementSession.remove(authenticationToken, TESTCLASSNAME);
        try {
            internalCertificateStoreSession.removeCertificate(ocspSigningCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }
        try {
            internalCertificateStoreSession.removeCertificate(caCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }
        try {
            internalCertificateStoreSession.removeCertificate(clientSSLCertificate);
        } catch (Exception e) {
            //Ignore any failures.
        }
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, authenticationKeyBindingId);
        internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, ocspKeyBindingId);
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        OcspTestUtils.deleteCa(authenticationToken, x509ca);
        // Ensure that the removed signing certificate is removed from the cache
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
    }
    
    @Test
    public void testKeyRenewal() throws Exception {
        assertNotEquals("This test cannot run without a ManagementCA that issued the localhost SSL certificate.", 0, managementCaId);
        // Make renewal call through our proxy
        ocspKeyRenewalProxySession.renewKeyStores("CN=ocspTestSigner");
        // Check that back-end InternalKeyBinding has been updated
        final String oldFingerprint = CertTools.getFingerprintAsString(ocspSigningCertificate);
        InternalKeyBinding ocspKeyBindingInfo = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(authenticationToken, ocspKeyBindingId);
        final String newFingerprint = ocspKeyBindingInfo.getCertificateId();
        final Certificate newOcspCertificate = certificateStoreSession.findCertificateByFingerprint(newFingerprint);
        assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", newFingerprint, oldFingerprint);
        // Check that OcspSigningCache has been updated
        final List<X509Certificate> cachedOcspCertificates = standaloneOcspResponseGeneratorTestSession.getCacheOcspCertificates();
        assertNotEquals("No OCSP certificates in cache after renewal!", 0, cachedOcspCertificates);
        boolean newCertificateExistsInCache = false;
        for (final X509Certificate cachedCertificate : cachedOcspCertificates) {
            if (CertTools.getFingerprintAsString(cachedCertificate).equals(newFingerprint)) {
                newCertificateExistsInCache = true;
                break;
            }
        }
        assertTrue("Renewed certificate does not exist in OCSP cache.", newCertificateExistsInCache);
        //Make sure that the new certificate is signed by the CA certificate
        try {
            newOcspCertificate.verify(caCertificate.getPublicKey());
        } catch (SignatureException e) {
            fail("The new signing certificate was not signed correctly.");
        }
    }

    // TODO: Use parts of the mock code below to also test renewal by the service

    /*
    private static KeyPair caKeys;
    private static X509Certificate caCertificate;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        caCertificate =  CertTools.genSelfCert(CA_DN, 365, null, caKeys.getPrivate(), caKeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
    }

    @Before
    public void setup() {
        //Dummy value to get past an assert
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.REKEYING_WSURL, "https://localhost:8443/ejbca/ejbcaws/ejbcaws");
    }
    
    / **
     * This is the most basic sanity test possible. Key renewal is tested with a DummyCryptoToken in place of a PKCS11, and the web service 
     * is replaced by a mock (as defined in OcspKeyRenewalProxySessionBean) that parrots the expected reply. 
     * /
    @Test
    public void testKeyRenewal() throws KeyStoreException, CryptoTokenOfflineException, InstantiationException, OCSPException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, IllegalStateException,
            NoSuchProviderException, OperatorCreationException, CertificateException, IOException, SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException {        
        X509Certificate cert = setupMockKeyStore();
        List<X509Certificate> oldValues = standaloneOcspResponseGeneratorTestSession.getCacheOcspCertificates();
        ocspKeyRenewalProxySession.renewKeyStores("CN=ocspTestSigner");
        List<X509Certificate> newValues = standaloneOcspResponseGeneratorTestSession.getCacheOcspCertificates();
        //Make sure that cache contains one and only one value
        assertEquals("Cache contains a different amount of values after rekeying than before. This indicates a test failure", oldValues.size(), newValues.size());
        //Make check that the certificate has changed (sanity check)
        X509Certificate newSigningCertificate = newValues.get(0);
        assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", cert.getSerialNumber(),
                newSigningCertificate.getSerialNumber());
        //Make sure that the new certificate is signed by the CA certificate
        try {
            newSigningCertificate.verify(caCertificate.getPublicKey());
        } catch (SignatureException e) {
            fail("The new signing certificate was not signed correctly.");
        }
    }
    
    / ** Test Key renewal using the automated update process. * /
    @Test
    public void testAutomaticKeyRenewal() throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            SignatureException, IllegalStateException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException,
            InstantiationException, OCSPException, InterruptedException, SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException, CryptoTokenOfflineException {
        X509Certificate cert = setupMockKeyStore();
        List<X509Certificate> oldValues = standaloneOcspResponseGeneratorTestSession.getCacheOcspCertificates();
        ocspKeyRenewalProxySession.setTimerToFireInOneSecond();
        Thread.sleep(2000);
        //Timer should have fired, and we should see some new stuff.
        List<X509Certificate> newValues = standaloneOcspResponseGeneratorTestSession.getCacheOcspCertificates();
        //Make sure that cache contains one and only one value
        assertEquals("Cache contains a different amount of values after rekeying than before. This indicates a test failure", oldValues.size(), newValues.size());
        //Make check that the certificate has changed (sanity check)
        X509Certificate newSigningCertificate = newValues.get(0);
        assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", cert.getSerialNumber(),
                newSigningCertificate.getSerialNumber());
        //Make sure that the new certificate is signed by the CA certificate
        try {
            newSigningCertificate.verify(caCertificate.getPublicKey());
        } catch (SignatureException e) {
            fail("The new signing certificate was not signed correctly.");
        }
 }
    
    / **
     * 
     * @return the ocsp signing certificate
     * @throws IllegalAccessException 
     * @throws NoSuchFieldException 
     * @throws IllegalArgumentException 
     * @throws SecurityException 
     * @throws CryptoTokenOfflineException
     * /
    private X509Certificate setupMockKeyStore() throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, SignatureException,
            IllegalStateException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, InstantiationException,
            OCSPException, SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException, CryptoTokenOfflineException {
        //Set a mock CryptoToken in the cache
        final String testAlias = "testAlias";
        //Map<Integer, CryptoTokenAndChain> newCache = new HashMap<Integer, CryptoTokenAndChain>();
        CryptoToken dummyCryptoToken = new DummyCryptoToken();
         
        //Generate the signer certificate
        Date firstDate = new Date();
        // Set starting date to tomorrow
        firstDate.setTime(firstDate.getTime());
        Date lastDate = new Date();
        // Set expiration to five minutes
        lastDate.setTime(lastDate.getTime() + (60 * 5 * 1000));
        BigInteger serno = SernoGeneratorRandom.instance().getSerno();
        SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence) ASN1Primitive.fromByteArray(caKeys.getPublic().getEncoded()));
        final X509NameEntryConverter converter = new X509DefaultEntryConverter();
        X500Name caName = CertTools.stringToBcX500Name(CA_DN, converter, false);
        ocspKeyRenewalProxySession.setManagementCaKeyPair(caKeys);
        ocspKeyRenewalProxySession.setCaDn(CA_DN);
        ocspKeyRenewalProxySession.setMockWebServiceObject();
        X500Name signerName = CertTools.stringToBcX500Name("CN=ocspTestSigner", converter, false);
        final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(caName, serno, firstDate, lastDate, signerName, pkinfo);
        final ContentSigner signer = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).build(caKeys.getPrivate());
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        final X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(certHolder.getEncoded());
        //X509Certificate[] certchain = { cert, caCertificate };
        try {
            cert.verify(caCertificate.getPublicKey());
        } catch (SignatureException e) {
            throw new RuntimeException();
        }
        //CryptoTokenAndChain testTokenAndChain = new CryptoTokenAndChain(dummyCryptoToken, certchain, testAlias);
        //newCache.put(Integer.valueOf(1337), testTokenAndChain);
        //standaloneOcspResponseGeneratorTestSession.replaceTokenAndChainCache(newCache);
        List<X509Certificate> caChain = Arrays.asList(new X509Certificate[]{caCertificate});
        standaloneOcspResponseGeneratorTestSession.replaceOcspSigningCache(caChain, cert, dummyCryptoToken.getPrivateKey(testAlias),
                dummyCryptoToken.getSignProviderName(), null);
        List<X509Certificate> oldValues = standaloneOcspResponseGeneratorTestSession.getCacheOcspCertificates();
        if (oldValues.size() < 1) {
            throw new RuntimeException("Cache contains no values. Something is messed up.");
        }
        if (oldValues.size() > 1) {
            throw new RuntimeException("Cache contains more than one value. Something is messed up.");
        }
        return cert;
    }*/
    
}
