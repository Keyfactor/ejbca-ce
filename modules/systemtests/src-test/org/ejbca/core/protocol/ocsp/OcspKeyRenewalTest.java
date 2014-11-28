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
package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.protocol.ocsp.standalone.OcspKeyRenewalProxySessionRemote;
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

    private static final String CA_DN = "CN=OcspDefaultTestCA,O=Foo,C=SE";
    private static final String CA_ECC_DN = "CN=OcspDefaultECCTestCA";
    private static final String OCSP_ECC_END_USER_NAME = OcspTestUtils.OCSP_END_USER_NAME+"Ecc";
    private static final String SIGNER_DN = "CN=ocspTestSigner";
    
    private static final String TESTCLASSNAME = OcspKeyRenewalTest.class.getSimpleName();
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASSNAME);
    private static final Logger log = Logger.getLogger(OcspKeyRenewalTest.class);
    
    private static final String ECC_CRYPTOTOKEN_NAME = TESTCLASSNAME+"ECC";

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private static CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityAccessSessionRemote.class);
    private OcspKeyRenewalProxySessionRemote ocspKeyRenewalProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
        OcspKeyRenewalProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private OcspResponseGeneratorTestSessionRemote standaloneOcspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(RoleManagementSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    private static X509CA x509ca;
    private static X509CA x509eccca;
    private static int cryptoTokenId;
    private static int cryptoTokenIdEcc;
    private static int ocspKeyBindingId;
    private static int ocspKeyBindingIdEcc;
    private static X509Certificate ocspSigningCertificate;
    private static X509Certificate ocspEccSigningCertificate;
    private static X509Certificate caCertificate;
    private static X509Certificate caEccCertificate;
    private static int authenticationKeyBindingId;
    private static X509Certificate clientSSLCertificate;
    private static int managementCaId = 0;
    private static List<Integer> disabledAuthenticationKeyBindings = new ArrayList<Integer>();

    @BeforeClass
    public static void beforeClass() throws Exception {
        cleanup();
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // - Disable any existing AuthenticationKeyBinding.
        final List<Integer> existingAuthenticationKeyBindings = internalKeyBindingMgmtSession.getInternalKeyBindingIds(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS);
        for (final Integer internalKeyBindingId : existingAuthenticationKeyBindings) {
            final InternalKeyBindingInfo internalKeyBindingInfo = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(authenticationToken, internalKeyBindingId);
            if (InternalKeyBindingStatus.ACTIVE.equals(internalKeyBindingInfo.getStatus())) {
                final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
                if (internalKeyBinding.getName().startsWith(TESTCLASSNAME)) {
                    log.debug("Ignoring test key binding "+internalKeyBinding.getName()+" ("+internalKeyBindingId+")");
                    continue;
                }
                log.info("Temporarly disabling existing AuthenticationKeyBinding with id " + internalKeyBindingId + " for the duration of this test.");
                internalKeyBinding.setStatus(InternalKeyBindingStatus.DISABLED);
                internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, internalKeyBinding);
                disabledAuthenticationKeyBindings.add(Integer.valueOf(internalKeyBindingId));
            }
        }
        
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, CA_DN);
        log.debug("OCSP CA Id: " + x509ca.getCAId() + " CA SubjectDN: " + x509ca.getSubjectDN());
        x509eccca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, CA_ECC_DN);
        log.debug("OCSP ECC CA Id: " + x509eccca.getCAId() + " CA SubjectDN: " + x509eccca.getSubjectDN());
        cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(authenticationToken, TESTCLASSNAME);
        cryptoTokenIdEcc = CryptoTokenTestUtils.createSoftCryptoToken(authenticationToken, ECC_CRYPTOTOKEN_NAME);
        ocspKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS, TESTCLASSNAME + "-ocsp", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        ocspKeyBindingIdEcc = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenIdEcc, OcspKeyBinding.IMPLEMENTATION_ALIAS, TESTCLASSNAME + "-ocspecc", "secp256r1", AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA);
        assertNotEquals("key binding Ids should not be the same", ocspKeyBindingId, ocspKeyBindingIdEcc);
        // We need an actual user for this OCSP signing certificate, so we can "renew" the certificate of this user
        EndEntityInformation user = new EndEntityInformation(OcspTestUtils.OCSP_END_USER_NAME, SIGNER_DN, x509ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        if (endEntityManagementSession.existsUser(OcspTestUtils.OCSP_END_USER_NAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME);
        }
        endEntityManagementSession.addUser(authenticationToken, user, true);
        // Now issue the cert for the user as well
        ocspSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, SIGNER_DN, ocspKeyBindingId, x509ca.getCAId());
        // RSA key right?
        assertEquals("Signing key algo should be RSA", AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmTools.getKeyAlgorithm(ocspSigningCertificate.getPublicKey()));
        // We need an actual user for this OCSP signing certificate, so we can "renew" the certificate of this user
        user = new EndEntityInformation(OCSP_ECC_END_USER_NAME, SIGNER_DN+"Ecc", x509eccca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        if (endEntityManagementSession.existsUser(OCSP_ECC_END_USER_NAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, OCSP_ECC_END_USER_NAME);
        }
        endEntityManagementSession.addUser(authenticationToken, user, true);
        // Now issue the cert for the user as well
        ocspEccSigningCertificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, OCSP_ECC_END_USER_NAME, SIGNER_DN+"Ecc", ocspKeyBindingIdEcc, x509eccca.getCAId());
        // ECC key right?
        assertEquals("Signing key algo should be EC", AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(ocspEccSigningCertificate.getPublicKey()));
        OcspTestUtils.updateInternalKeyBindingCertificate(authenticationToken, ocspKeyBindingId);
        OcspTestUtils.updateInternalKeyBindingCertificate(authenticationToken, ocspKeyBindingIdEcc);
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, ocspKeyBindingId, InternalKeyBindingStatus.ACTIVE);
        OcspTestUtils.setInternalKeyBindingStatus(authenticationToken, ocspKeyBindingIdEcc, InternalKeyBindingStatus.ACTIVE);
        caCertificate = ProtocolOcspHttpStandaloneTest.createCaCertificate(authenticationToken, x509ca.getCACertificate());
        caEccCertificate = ProtocolOcspHttpStandaloneTest.createCaCertificate(authenticationToken, x509eccca.getCACertificate());
        // Ensure that the new ocsp signing certificates are picked up by the cache
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        // Reuse the same CryptoToken for the client SSL authentication
        authenticationKeyBindingId = OcspTestUtils.createInternalKeyBinding(authenticationToken, cryptoTokenId, AuthenticationKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASSNAME + "-ssl", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
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
        // Create a new AuthenticationKeyBinding
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
        final String remotePort = SystemTestsConfiguration.getRemotePortHttps("8443");
        final String remoteHost = SystemTestsConfiguration.getRemoteHost("localhost");
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.REKEYING_WSURL, "https://"+remoteHost+":"+remotePort+"/ejbca/ejbcaws/ejbcaws");
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        cleanup();
        disabledAuthenticationKeyBindings = null; // static variable
    }
    
    private static void cleanup() throws Exception {
        try {
            roleManagementSession.remove(authenticationToken, TESTCLASSNAME);
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            // find all certificates for Ocsp signing user and remove them
            List<Certificate> certs = certificateStoreSession.findCertificatesByUsername(OcspTestUtils.OCSP_END_USER_NAME);
            for (Certificate certificate : certs) {
                internalCertificateStoreSession.removeCertificate(certificate);                
            }
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            // find all certificates for Ocsp signing user and remove them
            Collection<Certificate> certs = certificateStoreSession.findCertificatesBySubject(SIGNER_DN);
            for (Certificate certificate : certs) {
                internalCertificateStoreSession.removeCertificate(certificate);                
            }
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            // find all certificates for Ocsp ECC signing user and remove them
            List<Certificate> certs = certificateStoreSession.findCertificatesByUsername(OCSP_ECC_END_USER_NAME);
            for (Certificate certificate : certs) {
                internalCertificateStoreSession.removeCertificate(certificate);                
            }
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            // find all certificates for Ocsp ECC signing user and remove them
            Collection<Certificate> certs = certificateStoreSession.findCertificatesBySubject(SIGNER_DN+"Ecc");
            for (Certificate certificate : certs) {
                internalCertificateStoreSession.removeCertificate(certificate);                
            }
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            internalCertificateStoreSession.removeCertificate(caCertificate);
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            internalCertificateStoreSession.removeCertificate(caEccCertificate);
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        try {
            internalCertificateStoreSession.removeCertificate(clientSSLCertificate);
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
        
        // Delete KeyBindings
        cleanupKeyBinding(TESTCLASSNAME + "-ssl"); // authentication key binding
        cleanupKeyBinding(TESTCLASSNAME + "-ocsp"); // ocsp key binding
        cleanupKeyBinding(TESTCLASSNAME + "-ocspecc"); // ocsp key binding
        
        // Delete CryptoToken
        cleanupCryptoToken(TESTCLASSNAME);
        cleanupCryptoToken(ECC_CRYPTOTOKEN_NAME);
        
        // Delete CA
        final String caName = CertTools.getPartFromDN(CA_DN, "CN");
        try {
            while (true) {
                CAInfo info = caSession.getCAInfo(authenticationToken, caName);
                caSession.removeCA(authenticationToken, info.getCAId());
            }
        } catch (Exception e) {
            // Get out of loop and ignore
            log.debug(e.getMessage());
        }
        cleanupCryptoToken(caName);
        final String caEccName = CertTools.getPartFromDN(CA_ECC_DN, "CN");
        try {
            while (true) {
                CAInfo info = caSession.getCAInfo(authenticationToken, caEccName);
                caSession.removeCA(authenticationToken, info.getCAId());
            }
        } catch (Exception e) {
            // Get out of loop and ignore
            log.debug(e.getMessage());
        }
        cleanupCryptoToken(caEccName);
        
        if (endEntityAccessSession.findUser(authenticationToken, OCSP_ECC_END_USER_NAME) != null) {
            endEntityManagementSession.revokeAndDeleteUser(authenticationToken, OCSP_ECC_END_USER_NAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            log.debug("Cleaned up end-entity "+OCSP_ECC_END_USER_NAME);
        }
        if (endEntityAccessSession.findUser(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME) != null) {
            endEntityManagementSession.revokeAndDeleteUser(authenticationToken, OcspTestUtils.OCSP_END_USER_NAME, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            log.debug("Cleaned up end-entity "+OcspTestUtils.OCSP_END_USER_NAME);
        }
        
        for (final EndEntityInformation info : endEntityAccessSession.findUserBySubjectDN(authenticationToken, SIGNER_DN)) {
            endEntityManagementSession.revokeAndDeleteUser(authenticationToken, info.getUsername(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            log.debug("Cleaned up end-entity "+info.getUsername()+" with DN "+info.getDN());
        }
        for (final EndEntityInformation info : endEntityAccessSession.findUserBySubjectDN(authenticationToken, SIGNER_DN+"Ecc")) {
            endEntityManagementSession.revokeAndDeleteUser(authenticationToken, info.getUsername(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            log.debug("Cleaned up end-entity "+info.getUsername()+" with DN "+info.getDN());
        }
        
        // Re-enable temporarily disabled AuthenticationKeyBindings
        if (disabledAuthenticationKeyBindings!=null) {
            for (final Integer internalKeyBindingId : disabledAuthenticationKeyBindings) {
                try {
                    final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
                    if (internalKeyBinding.getName().startsWith(TESTCLASSNAME)) {
                        // If a test key binding is re-enabled after having been deleted, it will be created again!
                        log.debug("Skipping re-enable of test key binding "+internalKeyBinding.getName()+" ("+internalKeyBindingId+")");
                        continue;
                    }
                    log.info("Re-enabling existing AuthenticationKeyBinding with id " + internalKeyBindingId + " for the duration of this test.");
                    internalKeyBinding.setStatus(InternalKeyBindingStatus.ACTIVE);
                    internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, internalKeyBinding);
                } catch (InternalKeyBindingNameInUseException e) {
                    log.error(e.getMessage(), e);
                } catch (AuthorizationDeniedException e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
        // Ensure that the removed signing certificate is removed from the cache
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        
        log.debug("Successfully cleaned up test data");
    }
    
    private static void cleanupKeyBinding(String keybindingName) {
        try {
            // There can be more than one key binding if the test has failed multiple times
            while (true) {
                Integer keybindingId = internalKeyBindingMgmtSession.getIdFromName(keybindingName);
                if (keybindingId == null) break;
                if (internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, keybindingId)) {
                    log.debug("Cleaned up key binding after test: "+keybindingName+" ("+keybindingId+")");
                } else {
                    log.info("Key binding could not be deleted: "+keybindingName+" ("+keybindingId+")");
                }
            }
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
    }
    
    private static void cleanupCryptoToken(String name) {
        try {
            while (true) {
                Integer id = cryptoTokenManagementSession.getIdFromName(name); 
                if (id == null) break;
                cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, id);
            }
        } catch (Exception e) {
            //Ignore any failures.
            log.debug(e.getMessage());
        }
    }
    
    @Test
    public void testKeyRenewal() throws Exception {
        assertNotEquals("This test cannot run without a ManagementCA that issued the localhost SSL certificate.", 0, managementCaId);
        // Make renewal call through our proxy
        ocspKeyRenewalProxySession.renewKeyStores("CN=ocspTestSigner");
        // Old certificate has RSA key right?
        assertEquals("Signing key algo should be RSA", AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmTools.getKeyAlgorithm(ocspSigningCertificate.getPublicKey()));
        // Check that back-end InternalKeyBinding has been updated
        final String oldFingerprint = CertTools.getFingerprintAsString(ocspSigningCertificate);
        InternalKeyBinding ocspKeyBindingInfo = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(authenticationToken, ocspKeyBindingId);
        final String newFingerprint = ocspKeyBindingInfo.getCertificateId();
        final Certificate newOcspCertificate = certificateStoreSession.findCertificateByFingerprint(newFingerprint);
        assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", newFingerprint, oldFingerprint);
        // New certificate has RSA key right?
        assertEquals("Signing key algo should be RSA", AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmTools.getKeyAlgorithm(newOcspCertificate.getPublicKey()));
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

    @Test
    public void testKeyRenewalEcc() throws Exception {
        assertNotEquals("This test cannot run without a ManagementCA that issued the localhost SSL certificate.", 0, managementCaId);
        // Make renewal call through our proxy
        ocspKeyRenewalProxySession.renewKeyStores("CN=ocspTestSignerEcc");
        // Old certificate has ECC key right?
        assertEquals("Signing key algo should be ECC", AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(ocspEccSigningCertificate.getPublicKey()));
        // Check that back-end InternalKeyBinding has been updated
        final String oldFingerprint = CertTools.getFingerprintAsString(ocspEccSigningCertificate);
        InternalKeyBinding ocspKeyBindingInfo = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(authenticationToken, ocspKeyBindingIdEcc);
        final String newFingerprint = ocspKeyBindingInfo.getCertificateId();
        final Certificate newOcspCertificate = certificateStoreSession.findCertificateByFingerprint(newFingerprint);
        assertNotEquals("The same certificate was returned after the renewal process. Key renewal failed", newFingerprint, oldFingerprint);
        // New certificate has EC key right?
        assertEquals("Signing key algo should be ECC", AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(newOcspCertificate.getPublicKey()));
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
            newOcspCertificate.verify(caEccCertificate.getPublicKey());
        } catch (SignatureException e) {
            fail("The new signing certificate was not signed correctly.");
        }
    }

    @Test
    public void testAutomaticKeyRenewal() throws InvalidKeyException, KeyStoreException, CryptoTokenOfflineException, AuthorizationDeniedException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InterruptedException {
        if (managementCaId == 0) {
            throw new RuntimeException("This test cannot run without a ManagementCA that issued the localhost SSL certificate.");
        }
        ocspKeyRenewalProxySession.setTimerToFireInOneSecond();
        //Race condition, the WS object takes about two years to materialize
        Thread.sleep(10000);
        //Timer should have fired, and we should see some new stuff.

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
    
}
