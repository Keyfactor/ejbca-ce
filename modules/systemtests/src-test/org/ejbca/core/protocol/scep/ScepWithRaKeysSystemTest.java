/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.scep;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.string.StringConfigurationCache;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSession;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.cesecore.certificates.certificate.CertificateConstants.DATAENCIPHERMENT;
import static org.cesecore.certificates.certificate.CertificateConstants.DIGITALSIGNATURE;
import static org.cesecore.certificates.certificate.CertificateConstants.KEYENCIPHERMENT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Validate that EJBCA can use SCEP keys separate from the CA to decrypt SCEP
 * requests and sign SCEP responses.
 */
public class ScepWithRaKeysSystemTest {
    private static final String CA_DN = "CN=ScepWithRaKeys";
    private static final String SIGNING_CERTIFICATE_ALIAS = "SCEPSIGNER-systemtest";
    private static final String ENCRYPTION_CERTIFICATE_ALIAS = "SCEPENCRYPTOR-systemtest";
    private static final String SCEP_ENCRYPT_ALIAS = "scepEncrypt";
    private static final String SCEP_SIGN_ALIAS = "scepSign";

    // EJBs
    private final static CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final static GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final static ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final EndEntityManagementSession endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final CertificateCreateSession certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);

    private static ScepRaCertificateIssuer scepRaCertificateIssuer;
    private static X509CA ca;
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ScepTestBase"));
    private static String scepAlias = "scepwithrakeys";
    private static int cryptoTokenId;

    private ScepConfiguration scepConfiguration;
    private static X509Certificate encryptionCertificate;
    private static X509Certificate signingCertificate;

    @BeforeClass
    public static void beforeClass() throws Exception {
        // set up an issuing CA and the RA keys and certificates
        ca = CaTestUtils.createTestX509CA(CA_DN, "foo123".toCharArray(), false);
        caSession.addCA(admin, ca);
        cryptoTokenId = CryptoTokenTestUtils.createCryptoToken("foo123".toCharArray(), SoftCryptoToken.class.getName(), "scepencryption");
        cryptoTokenManagementSession.createKeyPair(admin, cryptoTokenId, SCEP_SIGN_ALIAS, KeyGenParams.builder("2048").build());
        cryptoTokenManagementSession.createKeyPair(admin, cryptoTokenId, SCEP_ENCRYPT_ALIAS, KeyGenParams.builder("2048").build());
        scepRaCertificateIssuer = new ScepRaCertificateIssuer(cryptoTokenManagementSession, caSession, endEntityManagementSession,
                certificateCreateSession);
        encryptionCertificate = scepRaCertificateIssuer.issueEncryptionCertificate(admin, ca.getName(), cryptoTokenId, SCEP_ENCRYPT_ALIAS);
        signingCertificate = scepRaCertificateIssuer.issueSigningCertificate(admin, ca.getName(), cryptoTokenId, SCEP_SIGN_ALIAS);

        StringConfigurationCache.INSTANCE.setEncryptionKey("qhrnf.f8743;12%#75".toCharArray());
    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        CaTestUtils.removeCa(admin, ca.getCAInfo());
        CryptoTokenTestUtils.removeCryptoToken(admin, cryptoTokenId);
        endEntityManagementSession.deleteUser(admin, "SCEP_RA_" + ca.getCAId());
    }

    @Before
    public void setUp() throws AuthorizationDeniedException, CertificateEncodingException {
        // set up a scep config that uses separate RA keys

        scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.removeAlias(scepAlias); // potentially clean up
        scepConfiguration.addAlias(scepAlias);
        scepConfiguration.setRAMode(scepAlias, true);
        scepConfiguration.setRADefaultCA(scepAlias, ca.getName());
        scepConfiguration.setRANameGenerationScheme(scepAlias, "DN");
        scepConfiguration.setRANameGenerationParameters(scepAlias, "CN");
        scepConfiguration.setRAAuthpassword(scepAlias, "foo123");
        scepConfiguration.setRAEndEntityProfile(scepAlias, "EMPTY");
        scepConfiguration.setRACertProfile(scepAlias, "ENDUSER");
        scepConfiguration.setCaChainRootFirstOrder(scepAlias, false);
        scepConfiguration.setIncludeCA(scepAlias, false);
        scepConfiguration.setEncryptionCryptoTokenId(scepAlias, cryptoTokenId);
        scepConfiguration.setEncryptionKeyAlias(scepAlias, SCEP_ENCRYPT_ALIAS);
        scepConfiguration.setEncryptionCertificate(scepAlias, CertTools.getPemFromCertificate(encryptionCertificate));
        scepConfiguration.setSigningCryptoTokenId(scepAlias, cryptoTokenId);
        scepConfiguration.setSigningKeyAlias(scepAlias, SCEP_SIGN_ALIAS);
        scepConfiguration.setSigningCertificate(scepAlias, CertTools.getPemFromCertificate(signingCertificate));
        globalConfigSession.saveConfiguration(admin, scepConfiguration);
    }

    @Test
    public void getCaCertsReturnsInExpectedOrder()
            throws AuthorizationDeniedException, IOException, InterruptedException, URISyntaxException, CertificateException {
        // get ejbca SCEP endpoint
        String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        String httpPort = SystemTestsConfiguration
                .getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        String resourceName = "/ejbca/publicweb/apply/scep/" + scepAlias + "/pkiclient.exe?operation=GetCACert&message=" + ca.getName();
        String url = "http://" + httpHost + ":" + httpPort + resourceName;

        // send the SCEP request and parse the response
        HttpResponse<byte[]> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(new URI(url)).GET().build(),
                BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode());

        // assert that it responds with the expected certificates in the expected order (encryption, issuing, signing)
        var certificates = CertificateFactory.getInstance("X509").generateCertificates(new ByteArrayInputStream(response.body())).stream()
                .map(c -> (X509Certificate) c).toList();
        assertEquals(3, certificates.size());
        assertEquals("CN=" + "SCEP_RA_" + ca.getCAId(), certificates.get(0).getSubjectX500Principal().getName());
        assertTrue(certificates.get(0).getKeyUsage()[KEYENCIPHERMENT]);
        assertEquals(CA_DN, certificates.get(1).getSubjectX500Principal().getName());
        assertEquals("CN=" + "SCEP_RA_" + ca.getCAId(), certificates.get(2).getSubjectX500Principal().getName());
        assertTrue(certificates.get(2).getKeyUsage()[DIGITALSIGNATURE]);
    }

    @Test
    public void usingRaKeysSucceeds() throws AuthorizationDeniedException, IOException, InterruptedException, URISyntaxException,
            CertificateException, OperatorCreationException, NoSuchAlgorithmException, CMSException {
        // get ejbca SCEP endpoint
        String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        String httpPort = SystemTestsConfiguration
                .getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        String resourceName = "/ejbca/publicweb/apply/scep/" + scepAlias + "/pkiclient.exe?operation=PKIOperation" + ca.getName();
        String url = "http://" + httpHost + ":" + httpPort + resourceName;

        // generate a SCEP request
        String userDN = "CN=twokeyscepclient";
        String transactionId = "1";
        final var keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        var keyPair = keyGenerator.generateKeyPair();
        //@formatter:off
        var senderCertificate = SimpleCertGenerator.forTESTLeafCert()
                .setSubjectDn(userDN).setIssuerDn(userDN)
                .setValidityDays(24 * 60 * 60 * 1000)
                .setIssuerPrivKey(keyPair.getPrivate())
                .setEntityPubKey(keyPair.getPublic())
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA)
                .generateCertificate();
        //@formatter:on
        var scepRequestGenerator = new ScepRequestGenerator();
        scepRequestGenerator.setKeys(keyPair, keyGenerator.getProvider().getName());
        var extensionGenerator = new ExtensionsGenerator();
        extensionGenerator.addExtension(Extension.keyUsage, false, new X509KeyUsage(0));
        var msgBytes = scepRequestGenerator.generateCertReq(userDN, "foo123", transactionId, encryptionCertificate, extensionGenerator.generate(),
                senderCertificate, keyPair.getPrivate(), PKCSObjectIdentifiers.rsaEncryption, CMSAlgorithm.AES256_CBC);

        // send the SCEP request and parse the response
        HttpResponse<byte[]> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(new URI(url))
                .header("Content-Type", "application/x-pki-message").POST(BodyPublishers.ofByteArray(msgBytes)).build(), BodyHandlers.ofByteArray());

        // This an interesting part of the test - we encrypted with `encryptionCertificate`, 
        // which is not the CAs key - so if the message is understood.  So a non-error means
        // EJBCA decrypted with the correct key
        assertEquals(200, response.statusCode());

        var signedData = new CMSSignedData(response.body());
        var signers = signedData.getSignerInfos().getSigners();
        assertTrue(signers.size() == 1);
        var signer = signers.iterator().next();
        var signatureCertificateIssuer = signer.getSID().getIssuer();
        var signatureCertificateSerialNumber = signer.getSID().getSerialNumber();
        var signedContent = signedData.getSignedContent();
        var cmsEnvelopedData = new CMSEnvelopedData((byte[]) signedContent.getContent());
        var recipientInformation = cmsEnvelopedData.getRecipientInfos().getRecipients().stream().findFirst().get();
        var innerSignedData = new CMSSignedData(recipientInformation.getContent(new JceKeyTransEnvelopedRecipient(keyPair.getPrivate())));
        var issuedCertificate = innerSignedData.getCertificates().getMatches(null).iterator().next();

        // this is another interesting part of the test - the signer of the response is the RA signer key
        assertEquals(signatureCertificateIssuer.toString(), signingCertificate.getIssuerX500Principal().getName());
        assertEquals(signatureCertificateSerialNumber, signingCertificate.getSerialNumber());

        // and the CA issued the certficate
        assertEquals(CA_DN, issuedCertificate.getIssuer().toString());
    }

    @Test
    public void issuedEncryptionCertificatesAreGood() throws Exception {
        // create a ca and SCEP ra token
        String testKeyAlias = "encKey";
        String testTokenName = "encryptioncerttest";
        var testCa = CaTestUtils.createTestX509CA("CN=EncryptionCertTest", "foo123".toCharArray(), false);
        caSession.addCA(admin, testCa);
        var testTokenId = CryptoTokenTestUtils.createCryptoToken("foo123".toCharArray(), SoftCryptoToken.class.getName(), testTokenName);
        cryptoTokenManagementSession.createKeyPair(admin, testTokenId, testKeyAlias, KeyGenParams.builder("2048").build());

        // issue the cert
        var scepCertIssuer = new ScepRaCertificateIssuer(cryptoTokenManagementSession, caSession, endEntityManagementSession,
                certificateCreateSession);
        var raEncryptionCertificate = scepCertIssuer.issueEncryptionCertificate(admin, testCa.getName(), testTokenId, testKeyAlias);
        
        // not a CA and has expected encryption cert usage
        assertEquals(-1, raEncryptionCertificate.getBasicConstraints());
        assertFalse(raEncryptionCertificate.getKeyUsage()[DIGITALSIGNATURE]);
        assertTrue(raEncryptionCertificate.getKeyUsage()[DATAENCIPHERMENT]);
        assertTrue(raEncryptionCertificate.getKeyUsage()[KEYENCIPHERMENT]);

        // clean up
        endEntityManagementSession.deleteUser(admin, "SCEP_RA_" + testCa.getCAId());
        CaTestUtils.removeCa(admin, testCa.getCAInfo());
        CryptoTokenTestUtils.removeCryptoToken(admin, testTokenId);
    };

    @Test
    public void issuedSigningCertificatesAreGood() throws Exception {
        // create a ca and SCEP ra token
        String testKeyAlias = "signKey";
        String testTokenName = "signingcerttest";
        var testCa = CaTestUtils.createTestX509CA("CN=SigningCertTest", "foo123".toCharArray(), false);
        caSession.addCA(admin, testCa);
        var testTokenId = CryptoTokenTestUtils.createCryptoToken("foo123".toCharArray(), SoftCryptoToken.class.getName(), testTokenName);
        cryptoTokenManagementSession.createKeyPair(admin, testTokenId, testKeyAlias, KeyGenParams.builder("2048").build());

        // issue the cert
        var scepCertIssuer = new ScepRaCertificateIssuer(cryptoTokenManagementSession, caSession, endEntityManagementSession,
                certificateCreateSession);
        var raEncryptionCertificate = scepCertIssuer.issueSigningCertificate(admin, testCa.getName(), testTokenId, testKeyAlias);
        
        // not a CA and has expected encryption cert usage
        assertEquals(-1, raEncryptionCertificate.getBasicConstraints());
        assertTrue(raEncryptionCertificate.getKeyUsage()[DIGITALSIGNATURE]);
        assertFalse(raEncryptionCertificate.getKeyUsage()[DATAENCIPHERMENT]);
        assertFalse(raEncryptionCertificate.getKeyUsage()[KEYENCIPHERMENT]);

        // clean up
        endEntityManagementSession.deleteUser(admin, "SCEP_RA_" + testCa.getCAId());
        CaTestUtils.removeCa(admin, testCa.getCAInfo());
        CryptoTokenTestUtils.removeCryptoToken(admin, testTokenId);
    };

}
