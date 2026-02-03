/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import com.keyfactor.util.keys.token.KeyGenParams;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.DatabaseMaintenanceWorker;
import org.ejbca.core.model.services.workers.DatabaseMaintenanceWorkerConstants;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * System tests of DatabaseMaintenanceWorker
 */
public class DatabaseMaintenanceWorkerSystemTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(DatabaseMaintenanceWorkerSystemTest.class);

    private static final Date CRL_ENTRY_REVOCATION_DATE = new GregorianCalendar(2022, Calendar.JULY, 3).getTime();
    private static final Date CRL_ENTRY_INVALIDITY_DATE = new GregorianCalendar(2021, Calendar.OCTOBER, 1).getTime();
    private static final String TEST_SERVICE_NAME = "DatabaseMaintenanceWorkerSystemTest_service";
    private static final String TEST_CERTIFICATE_USERNAME = "DatabaseMaintenanceWorkerSystemTest_user";
    private static final String TEST_DN_SUFFIX = ",OU=DatabaseMaintenanceWorkerSystemTest,O=Test";
    private static final String DN_OLD = "CN=old" + TEST_DN_SUFFIX;
    private static final String DN_JUSTEXPIRED = "CN=just_expired" + TEST_DN_SUFFIX;
    private static final String DN_NOTEXPIRED = "CN=not_expired" + TEST_DN_SUFFIX;
    private static final String TEST_PRIVKEY_PEM = // ed25519 key
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MC4CAQAwBQYDK2VwBCIEIFFysGvjXrPaKPhD95+aAIuQYA8sEBRBLme6v7TaQ+kx\n" +
                    "-----END PRIVATE KEY-----";

    private static final String CA_NAME = "DatabaseMaintenanceWorkerSystemTest_ca";
    private static final String ISSUER_DN = "CN=" + CA_NAME + ",O=Test";

    private static final String TEST_CAPRIVKEY_PEM = // ed25519 key
            "-----BEGIN PRIVATE KEY-----\n" +
                    "MC4CAQAwBQYDK2VwBCIEIHO09bDUXqT3RpaM8w1XDSFeZFtPzFX+o14/RmEknNMI\n" +
                    "-----END PRIVATE KEY-----";

    private final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("DatabaseMaintenanceWorkerSystemTest");
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);

    // For the test certificate
    private final KeyPair certKeyPair = KeyTools.getKeyPairFromPEM(TEST_PRIVKEY_PEM);
    // For the CA
    private final KeyPair caKeyPair =  KeyTools.getKeyPairFromPEM(TEST_CAPRIVKEY_PEM);
    private Certificate caCert;
    private CAInfo caInfo;
    private String caFingerprint;

    @BeforeClass
    public static void beforeClass() {
        log.trace(">beforeClass");
        CryptoProviderTools.installBCProviderIfNotAvailable();
        log.trace("<beforeClass");
    }

    @After
    public void cleanup() throws AuthorizationDeniedException {
        log.trace(">cleanup");
        internalCertificateStoreSession.removeCertificatesByUsername(TEST_CERTIFICATE_USERNAME);
        serviceSession.removeService(admin, TEST_SERVICE_NAME);
        if (caInfo != null) {
            int caId = caInfo.getCAId();
            caSession.removeCA(admin, caId);
        }
        internalCertificateStoreSession.removeCertificatesBySubject(ISSUER_DN);
        crlStoreSession.removeByIssuerDN(ISSUER_DN);
        log.trace("<cleanup");
    }

    @Test
    public void testCertificateCleanup() throws Exception {
        log.trace(">testCertificateCleanup");
        // Given
        assertFalse("Certificate should not exist prior to running the test.", certificateExists(DN_OLD));
        addCa();
        addCertificate(DN_OLD, -1000, TimeUnit.DAYS);
        addCertificate(DN_JUSTEXPIRED, -3, TimeUnit.DAYS);
        addCertificate(DN_NOTEXPIRED, 10, TimeUnit.DAYS);
        assertTrue("Old certificate should exist at start.", certificateExists(DN_OLD));
        assertTrue("Recently expired certificate should exist at start.", certificateExists(DN_JUSTEXPIRED));
        assertTrue("Non-expired certificate should exist at start.", certificateExists(DN_NOTEXPIRED));
        addService();
        // Let service run
        Thread.sleep(1500);
        // Then
        assertFalse("Old certificate should have been deleted.", certificateExists(DN_OLD));
        assertTrue("Recently expired certificate should still exist (due to delay setting).", certificateExists(DN_JUSTEXPIRED));
        assertTrue("Non-expired certificate should still exist.", certificateExists(DN_NOTEXPIRED));
        log.trace("<testCertificateCleanup");
    }

    @Test
    public void testCrlCleanup() throws Exception {
        log.trace(">testCrlCleanup");
        // Given
        addCa();

        BigInteger crlOneNumber = BigInteger.valueOf(1L);
        addCrl(CrlGenParamHolder.newBuilder()
                .withCrlNumber(crlOneNumber)
                .withissuerDn(ISSUER_DN)
                .withExpirationFromNow(-9)
                .withExpirationTimeUnit(TimeUnit.DAYS)
                .build());

        BigInteger deltaCrlOneNumber = BigInteger.valueOf(2L);
        addCrl(CrlGenParamHolder.newBuilder()
                .withCrlNumber(deltaCrlOneNumber)
                .withissuerDn(ISSUER_DN)
                .withIsDelta(true)
                .withBaseCrlNumber(crlOneNumber)
                .withExpirationFromNow(-8)
                .withExpirationTimeUnit(TimeUnit.DAYS)
                .build());

        BigInteger crlTwoNumber = BigInteger.valueOf(3L);
        addCrl(CrlGenParamHolder.newBuilder()
                .withCrlNumber(crlTwoNumber)
                .withissuerDn(ISSUER_DN)
                .withExpirationFromNow(-5)
                .withExpirationTimeUnit(TimeUnit.DAYS)
                .build());

        BigInteger deltaCrlTwoNumber = BigInteger.valueOf(4L);
        addCrl(CrlGenParamHolder.newBuilder()
                .withCrlNumber(deltaCrlTwoNumber)
                .withissuerDn(ISSUER_DN)
                .withIsDelta(true)
                .withBaseCrlNumber(crlTwoNumber)
                .withExpirationFromNow(-3)
                .withExpirationTimeUnit(TimeUnit.DAYS)
                .build());

        assertTrue(crlExists(ISSUER_DN, crlOneNumber));
        assertTrue(crlExists(ISSUER_DN, crlTwoNumber));
        assertTrue(crlExists(ISSUER_DN, deltaCrlOneNumber));
        assertTrue(crlExists(ISSUER_DN, deltaCrlTwoNumber));

        addService();
        Thread.sleep(1500);

        // Then
        assertFalse(crlExists(ISSUER_DN, crlOneNumber));
        assertTrue(crlExists(ISSUER_DN, crlTwoNumber));
        assertFalse(crlExists(ISSUER_DN, deltaCrlOneNumber));
        assertTrue(crlExists(ISSUER_DN, deltaCrlTwoNumber));

        log.trace("<testCrlCleanup");
    }

    private boolean crlExists(String issuerDn, BigInteger crlNumber) {
        return crlStoreSession.getCRL(issuerDn, CertificateConstants.NO_CRL_PARTITION, crlNumber.intValue()) != null;
    }

    private boolean certificateExists(final String subjectDn) {
        return !certificateStoreSession.findCertificatesBySubject(subjectDn).isEmpty();
    }

    private void addService() throws ServiceExistsException {
        final ServiceConfiguration serviceConfig = new ServiceConfiguration();
        serviceConfig.setActive(true);
        serviceConfig.setDescription("Used in test");
        serviceConfig.setWorkerClassPath(DatabaseMaintenanceWorkerConstants.WORKER_CLASS);
        serviceConfig.setActionClassPath(NoAction.class.getCanonicalName());
        serviceConfig.setIntervalClassPath(PeriodicalInterval.class.getCanonicalName());
        final Properties intervalProperties = new Properties();
        intervalProperties.setProperty(PeriodicalInterval.PROP_VALUE, "1");
        intervalProperties.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
        serviceConfig.setIntervalProperties(intervalProperties);
        final Properties props = serviceConfig.getWorkerProperties();
        props.put(DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CERTIFICATES, Boolean.TRUE.toString());
        props.put(DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CRLS, Boolean.TRUE.toString());
        props.put(DatabaseMaintenanceWorkerConstants.PROP_BATCH_SIZE, "100");
        props.put(DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEVALUE, "5");
        props.put(DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEUNIT, IWorker.UNIT_DAYS);
        props.put(DatabaseMaintenanceWorker.PROP_CAIDSTOCHECK, String.valueOf(caInfo.getCAId()));
        serviceSession.addService(admin, TEST_SERVICE_NAME, serviceConfig);
        serviceSession.activateServiceTimer(admin, TEST_SERVICE_NAME);
    }

    private void addCrl(CrlGenParamHolder paramHolder) throws Exception {
        byte[] crlAsBytes = generateCrl(CrlGenParamHolder.newBuilder()
                .withExpirationFromNow(paramHolder.expirationFromNow)
                .withCrlNumber(paramHolder.crlNumber)
                .withIsDelta(paramHolder.isDelta)
                .withBaseCrlNumber(paramHolder.baseCrlNumber)
                .build());
        final long expirationTime = System.currentTimeMillis() + paramHolder.expirationTimeUnit.toMillis(paramHolder.expirationFromNow);
        X509CRL crl = CertTools.getCRLfromByteArray(crlAsBytes);
        String fingerprint = CertTools.getFingerprintAsString(caCert);
        int deltaIndicator = -1;
        if (paramHolder.isDelta) {
            deltaIndicator = 1;
        }
        crlStoreSession.storeCRL(admin, crlAsBytes, fingerprint, paramHolder.crlNumber.intValue(), paramHolder.issuerDn, CertificateConstants.NO_CRL_PARTITION,
                crl.getThisUpdate(), new Date(expirationTime), deltaIndicator);
    }

    private byte[] generateCrl(CrlGenParamHolder paramHolder) throws Exception {
        X500Name issuer = X500Name.getInstance(((X509Certificate) caCert).getSubjectX500Principal().getEncoded());
        final long expirationTime = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(paramHolder.expirationFromNow);
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuer, new Date(expirationTime));
        crlGen.addCRLEntry(BigInteger.ONE, CRL_ENTRY_REVOCATION_DATE, 3, CRL_ENTRY_INVALIDITY_DATE);
        crlGen.addExtension(Extension.cRLNumber, true, new CRLNumber(paramHolder.crlNumber));
        if (paramHolder.isDelta) {
            CRLNumber baseCrlNum = new CRLNumber(paramHolder.crlNumber);
            crlGen.addExtension(Extension.deltaCRLIndicator, true, baseCrlNum);
        }
        return crlGen.build(new BufferingContentSigner(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_ED25519)
                        .setProvider(CryptoProviderTools.getProviderNameFromAlg(AlgorithmConstants.SIGALG_ED25519))
                        .build(caKeyPair.getPrivate())))
                .getEncoded();
    }

    private void addCa() throws Exception {
        caCert = SimpleCertGenerator.forTESTCaCert()
                .setSubjectDn(ISSUER_DN)
                .setIssuerDn(ISSUER_DN)
                .setValidityDays(14)
                .setIssuerPrivKey(caKeyPair.getPrivate())
                .setEntityPubKey(caKeyPair.getPublic())
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_ED25519)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setLdapOrder(false)
                .generateCertificate();
        caFingerprint = CertTools.getFingerprintAsString(caCert);
        try {
            caAdminSession.importCACertificate(admin, CA_NAME, Collections.singleton(EJBTools.wrap(caCert)));
        } catch (CAExistsException e) {
            log.warn("Test CA already exists!?");
        }
        caInfo = caSession.getCAInfo(admin, CA_NAME);
    }

    private X509Certificate addCertificate(final String subjectDn, long expirationFromNow, TimeUnit expirationTimeUnit)
            throws AuthorizationDeniedException, OperatorCreationException, CertificateException, CertIOException {
        final long expirationTime = System.currentTimeMillis() + expirationTimeUnit.toMillis(expirationFromNow);
        final Certificate certificate = SimpleCertGenerator.forTESTLeafCert()
                .setSubjectDn(subjectDn)
                .setIssuerDn(ISSUER_DN)
                .setFirstDate(new Date(expirationTime - TimeUnit.DAYS.toMillis(30)))
                .setLastDate(new Date(expirationTime))
                .setIssuerPrivKey(caKeyPair.getPrivate())
                .setEntityPubKey(certKeyPair.getPublic())
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_ED25519)
                .setKeyUsage(CertificateConstants.DIGITALSIGNATURE)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setLdapOrder(false)
                .generateCertificate();
                
        final CertificateWrapper certWrapper = new CertificateDataWrapper(certificate, null, null);
        certificateStoreSession.storeCertificateRemote(admin, certWrapper, TEST_CERTIFICATE_USERNAME, caFingerprint,
                CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateConstants.NO_CRL_PARTITION, null, System.currentTimeMillis(), "");
        return (X509Certificate) certificate;
    }

    @Test
    public void testKeyBindingCertificateNotDeleted() throws Exception {
        log.trace(">testKeyBindingCertificateNotDeleted");
        
        // Given: Create CA and certificates
        assertFalse("Certificate should not exist prior to running the test.", certificateExists(DN_OLD));
        addCa();
        
        // Create an expired certificate for a key binding
        final String keyBindingCertDn = "CN=keybinding_cert" + TEST_DN_SUFFIX;
        final X509Certificate keyBindingCert = addCertificate(keyBindingCertDn, -1000, TimeUnit.DAYS);
        final String keyBindingCertFingerprint = CertTools.getFingerprintAsString(keyBindingCert);
        
        // Create an expired certificate NOT used by a key binding
        addCertificate(DN_OLD, -1000, TimeUnit.DAYS);
        
        assertTrue("Key binding certificate should exist at start.", certificateExists(keyBindingCertDn));
        assertTrue("Old certificate should exist at start.", certificateExists(DN_OLD));
        
        // Create a crypto token for the key binding
        final int cryptoTokenId = createCryptoToken();
        
        // Create an internal key binding that references the expired certificate
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = 
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        
        final String keyBindingName = "testKeyBinding_" + System.currentTimeMillis();
        final int keyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(
            admin,
            "OcspKeyBinding",
            keyBindingName,
            InternalKeyBindingStatus.ACTIVE,
            keyBindingCertFingerprint,
            cryptoTokenId,
            "testKey",
            AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA,
            new HashMap<>(),
            Collections.emptyList()
        );
        
        // Verify the certificate exists in the database before running the service
        final CertificateStoreSessionRemote certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        final Certificate certFromDb = certStoreSession.findCertificateByFingerprint(keyBindingCertFingerprint);
        assertNotNull("Certificate should exist.", certFromDb);
        final String dbFingerprint = CertTools.getFingerprintAsString(certFromDb);
        assertEquals("Fingerprints should match.", keyBindingCertFingerprint.toLowerCase(), dbFingerprint.toLowerCase());
        
        // Verify the key binding exists and has the correct certificate ID
        final InternalKeyBinding retrievedBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(admin, keyBindingId);
        assertNotNull("Key binding should exist.", retrievedBinding);
        
        try {
            // Add and run the service AFTER creating the key binding
            addService();
            Thread.sleep(3000);
            
            // Then: Verify that the key binding certificate was NOT deleted
            assertTrue("Key binding certificate should NOT have been deleted (still in use).", 
                certificateExists(keyBindingCertDn));
            
            // But the old certificate not used by any key binding should be deleted
            assertFalse("Old certificate should have been deleted.", certificateExists(DN_OLD));
            
        } finally {
            // Cleanup
            if (keyBindingId != 0) {
                internalKeyBindingMgmtSession.deleteInternalKeyBinding(admin, keyBindingId);
            }
            deleteCryptoToken(cryptoTokenId);
        }
        
        log.trace("<testKeyBindingCertificateNotDeleted");
    }

    @Test
    public void testUnusedKeyBindingCertificateIsDeleted() throws Exception {
        log.trace(">testUnusedKeyBindingCertificateIsDeleted");
        
        // Given: Create CA and certificates
        addCa();
        
        // Create an expired certificate
        final String expiredCertDn = "CN=expired_unused_cert" + TEST_DN_SUFFIX;
        addCertificate(expiredCertDn, -1000, TimeUnit.DAYS);
        
        assertTrue("Expired certificate should exist at start.", certificateExists(expiredCertDn));
        
        // Add and run the service (no key binding references this certificate)
        addService();
        Thread.sleep(3000);
        
        // Then: Verify that the certificate WAS deleted (not in use by any key binding)
        assertFalse("Expired certificate should have been deleted (not in use).", 
            certificateExists(expiredCertDn));
        
        log.trace("<testUnusedKeyBindingCertificateIsDeleted");
    }

    private int createCryptoToken() throws Exception {
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = 
            EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        
        final String cryptoTokenName = "testCryptoToken_" + System.currentTimeMillis();
        final Properties props = new Properties();
        props.setProperty("autoactivate", "foo123");
        
        final int cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(
            admin, 
            cryptoTokenName, 
            SoftCryptoToken.class.getName(), 
            props, 
            null, 
            null
        );
        
        // Activate the crypto token
        cryptoTokenManagementSession.activate(admin, cryptoTokenId, "foo123".toCharArray());
        
        // Generate a key pair
        cryptoTokenManagementSession.createKeyPair(
            admin, 
            cryptoTokenId, 
            "testKey", 
            KeyGenParams.builder("secp256r1").build()
        );
        
        return cryptoTokenId;
    }

    private void deleteCryptoToken(final int cryptoTokenId) throws Exception {
        if (cryptoTokenId != 0) {
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = 
                EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            cryptoTokenManagementSession.deleteCryptoToken(admin, cryptoTokenId);
        }
    }

    private static class CrlGenParamHolder {
        private final BigInteger crlNumber;
        private final boolean isDelta;
        private final BigInteger baseCrlNumber;
        private final String issuerDn;
        private final long expirationFromNow;
        private final TimeUnit expirationTimeUnit;

        public CrlGenParamHolder(Builder builder) {
            crlNumber = builder.crlNumber;
            isDelta = builder.isDelta;
            baseCrlNumber = builder.baseCrlNumber;
            issuerDn = builder.issuerDn;
            expirationFromNow = builder.expirationFromNow;
            expirationTimeUnit = builder.expirationTimeUnit;
        }

        static Builder newBuilder() {
            return new Builder();
        }

        static class Builder {
            private BigInteger crlNumber;
            private String issuerDn;
            private boolean isDelta;
            private BigInteger baseCrlNumber;
            private long expirationFromNow;
            private TimeUnit expirationTimeUnit;

            Builder withCrlNumber(BigInteger crlNumber) {
                this.crlNumber = crlNumber;
                return this;
            }

            Builder withissuerDn(String issuerDn) {
                this.issuerDn = issuerDn;
                return this;
            }

            Builder withExpirationFromNow(long expirationFromNow) {
                this.expirationFromNow = expirationFromNow;
                return this;
            }

            Builder withExpirationTimeUnit(TimeUnit expirationTimeUnit) {
                this.expirationTimeUnit = expirationTimeUnit;
                return this;
            }

            Builder withIsDelta(boolean isDelta) {
                this.isDelta = isDelta;
                return this;
            }

            Builder withBaseCrlNumber(BigInteger baseCrlNumber) {
                this.baseCrlNumber = baseCrlNumber;
                return this;
            }

            CrlGenParamHolder build() {
                return new CrlGenParamHolder(this);
            }
        }
    }

}