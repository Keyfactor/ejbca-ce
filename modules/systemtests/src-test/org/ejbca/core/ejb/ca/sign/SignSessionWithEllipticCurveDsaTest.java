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
package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** Test signing certificates with ECDSA public keys, from CAs with RSA and ECDSA keys
 */
public class SignSessionWithEllipticCurveDsaTest extends SignSessionCommon {

    private static final Logger log = Logger.getLogger(SignSessionWithEllipticCurveDsaTest.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "EllipticCurveDsaSignSessionTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final String RSA_USERNAME = "RsaUser";
    private static final String ECDSA_USERNAME = "EcdsaUser";
    private static final String DEFAULT_EE_PROFILE = "ECDSAEEPROFILE";
    private static final String DEFAULT_CERTIFICATE_PROFILE = "ECDSACERTPROFILE";

    private static KeyPair ecdsakeys;

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();

        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        createTestCA();
        createEllipticCurveDsaCa();

        int rsacaid = caSession.getCAInfo(internalAdmin, getTestCAName()).getCAId();
        createEndEntity(RSA_USERNAME, DEFAULT_EE_PROFILE, DEFAULT_CERTIFICATE_PROFILE, rsacaid);
        createEcdsaEndEntity();
        ecdsakeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        cleanUpEndEntity(RSA_USERNAME);
        cleanUpEndEntity(ECDSA_USERNAME);
        removeTestCA();
        removeTestCA(TEST_ECDSA_CA_NAME);
    }

    @Test
    public void testSignSessionECDSAWithRSACA() throws Exception {
        log.trace(">test12SignSessionECDSAWithRSACA()");
        endEntityManagementSession.setUserStatus(internalAdmin, RSA_USERNAME, EndEntityConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, RSA_USERNAME, "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        // We need to convert to BC to avoid differences between JDK7 and JDK8, and supported curves
        X509Certificate bccert = CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
        PublicKey pk = bccert.getPublicKey();
        checkECKey(pk);
        try {
            X509Certificate rsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, getTestCAName()).getCertificateChain().toArray()[0];
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            fail("Failed to verify the returned certificate with CAs public key: " + e.getMessage());
        }
        log.trace("<test12SignSessionECDSAWithRSACA()");
    }

    private void checkECKey(PublicKey pk) {
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("Only ImplicitlyCA curves can have null spec", spec);
        } else if (pk instanceof BCECPublicKey) {
            BCECPublicKey ecpk = (BCECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("Only ImplicitlyCA curves can have null spec", spec);
        } else {
            fail("Public key is not EC: "+pk.getClass().getName());
        }        
    }

    /**
     * tests bouncy PKCS10
     * 
     */
    @Test
    public void testBCPKCS10ECDSAWithRSACA() throws Exception {
        log.trace(">test13TestBCPKCS10ECDSAWithRSACA()");

        endEntityManagementSession.setUserStatus(internalAdmin, RSA_USERNAME, EndEntityConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foo"),
                ecdsakeys.getPublic(), new DERSet(), ecdsakeys.getPrivate(), null);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);
        dOut.writeObject(req.toASN1Structure());
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(ecdsakeys.getPublic());
        boolean verify = req2.isSignatureValid(verifier);
        log.debug("Verify returned " + verify);
        assertTrue("Can't verify the newly created POP on PKCS#10 CSR", verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername(RSA_USERNAME);
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        checkECKey(pk);
        try {
            X509Certificate rsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, getTestCAName()).getCertificateChain().toArray()[0];
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            fail("Failed to verify the returned certificate with CAs public key: " + e.getMessage());
        }
        log.trace("<test13TestBCPKCS10ECDSAWithRSACA()");
    }

    @Test
    public void testSignSessionECDSAWithECDSACA() throws Exception {
        log.trace(">test14SignSessionECDSAWithECDSACA()");
        endEntityManagementSession.setUserStatus(internalAdmin, ECDSA_USERNAME, EndEntityConstants.STATUS_NEW);
        log.debug("Reset status of '" + ECDSA_USERNAME + "' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, ECDSA_USERNAME, "foo123", selfcert);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        // We need to convert to BC to avoid differences between JDK7 and JDK8, and supported curves
        X509Certificate bccert = CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
        PublicKey pk = bccert.getPublicKey();
        checkECKey(pk);
        X509Certificate ecdsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_ECDSA_CA_NAME).getCertificateChain().toArray()[0];
        try {
            cert.verify(ecdsacacert.getPublicKey());
        } catch (Exception e) {
            fail("Failed to verify the returned certificate with CAs public key: " + e.getMessage());
        }
        log.trace("<test14SignSessionECDSAWithECDSACA()");
    }

    /**
     * tests bouncy PKCS10
     */
    @Test
    public void testBCPKCS10ECDSAWithECDSACA() throws Exception {
        testBCPKCS10ECDSAWithECDSACA(ecdsakeys);
    }
    /**
     * tests bouncy PKCS10 with Brainpool EC curve
     */
    @Test
    public void testBCPKCS10ECDSABrainppolWithECDSACA() throws Exception {
        KeyPair keys = KeyTools.genKeys("brainpoolP160r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        testBCPKCS10ECDSAWithECDSACA(keys);
    }
    private void testBCPKCS10ECDSAWithECDSACA(KeyPair keys) throws Exception {
        log.trace(">test15TestBCPKCS10ECDSAWithECDSACA()");

        endEntityManagementSession.setUserStatus(internalAdmin, ECDSA_USERNAME, EndEntityConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN="
                + ECDSA_USERNAME), keys.getPublic(), new DERSet(), keys.getPrivate(), null);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);
        dOut.writeObject(req.toASN1Structure());
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(keys.getPublic());
        boolean verify = req2.isSignatureValid(verifier);
        log.debug("Verify returned " + verify);
        assertTrue("Can't verify the newly created POP on PKCS#10 CSR", verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername(ECDSA_USERNAME);
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        checkECKey(pk);
        try {
            X509Certificate ecdsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_ECDSA_CA_NAME).getCertificateChain().toArray()[0];
            cert.verify(ecdsacacert.getPublicKey());
        } catch (Exception e) {
            fail("Failed to verify the returned certificate with CAs public key: " + e.getMessage());
        }
        log.trace("<test15TestBCPKCS10ECDSAWithECDSACA()");
    }

    @Test
    public void testMatterIoT() throws Exception {
        log.trace(">testMatterIoT()");
        final String profileName = "TESTMATTERIOT";
        final String endEntityName = "TESTMATTERIOT";
        // Create a standard certificate profile (good enough)
        certificateProfileSession.removeCertificateProfile(internalAdmin, profileName);
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfileSession.addCertificateProfile(internalAdmin, profileName, certprof);
        int cprofile = certificateProfileSession.getCertificateProfileId(profileName);

        // Create a good end entity profile
        endEntityProfileSession.removeEndEntityProfile(internalAdmin, profileName);
        EndEntityProfile profile = new EndEntityProfile();
        profile.addField(DnComponents.COUNTRY);
        profile.addField(DnComponents.ORGANIZATION);
        profile.addField(DnComponents.COMMONNAME);
        profile.addField(DnComponents.VID);
        profile.addField(DnComponents.PID);
        profile.setAvailableCAs(Collections.singleton(SecConst.ALLCAS));
        profile.setAvailableCertificateProfileIds(Collections.singleton(cprofile));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, profileName, profile);
        KeyPair anotherKey = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        int rsacaid = caSession.getCAInfo(internalAdmin, getTestCAName()).getCAId();
        int eeprofile = endEntityProfileSession.getEndEntityProfileId(profileName);
        createEndEntity(endEntityName, eeprofile, cprofile, rsacaid);
        try {
    
            EndEntityInformation user = new EndEntityInformation(endEntityName, "C=SE,O=PrimeKey,CN=Matter DAC,VID=FFF1,PID=8000", rsacaid, null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), eeprofile, cprofile, SecConst.TOKEN_SOFT_BROWSERGEN, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.changeUser(internalAdmin, user, false);
            log.debug("created user: " + endEntityName + ", foo123, C=SE,O=PrimeKey,CN=Matter DAC,VID=FFF1,PID=8000");
            X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, endEntityName, "foo123", new PublicKeyWrapper(anotherKey.getPublic()));
            assertNotNull("Failed to create certificate", cert);
            String dn = cert.getSubjectDN().getName();
            // This is the reverse order than what is displayed by openssl, the fields are no known by JDK so OIDs displayed
            assertEquals("Not the expected DN in issued cert", "C=SE, O=PrimeKey, CN=Matter DAC, OID.1.3.6.1.4.1.37244.2.1=FFF1, OID.1.3.6.1.4.1.37244.2.2=8000", dn);
            assertEquals("Not the expected EJBCA ordered DN in issued cert", "PID=8000,VID=FFF1,CN=Matter DAC,O=PrimeKey,C=SE", CertTools.getSubjectDN(cert));

            // Change to X509 DN order
            certprof.setUseLdapDnOrder(false);
            certificateProfileSession.changeCertificateProfile(internalAdmin, profileName, certprof);
            endEntityManagementSession.changeUser(internalAdmin, user, false);
            cert = (X509Certificate) signSession.createCertificate(internalAdmin, endEntityName, "foo123", new PublicKeyWrapper(anotherKey.getPublic()));
            assertNotNull("Failed to create certificate", cert);
            dn = cert.getSubjectDN().getName();
            // This is the reverse order than what is displayed by openssl
            assertEquals("Not the expected DN in issued cert", "OID.1.3.6.1.4.1.37244.2.2=8000, OID.1.3.6.1.4.1.37244.2.1=FFF1, CN=Matter DAC, O=PrimeKey, C=SE", dn);
            assertEquals("Not the expected EJBCA ordered DN in issued cert", "PID=8000,VID=FFF1,CN=Matter DAC,O=PrimeKey,C=SE", CertTools.getSubjectDN(cert));
        } finally {
            // Clean up
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, profileName);
            certificateProfileSession.removeCertificateProfile(internalAdmin, profileName);
            endEntityManagementSession.deleteUser(internalAdmin, endEntityName);
            internalCertStoreSession.removeCertificatesByUsername(endEntityName);
        }
        log.trace("<testMatterIoT()");
    }

    @Override
    public String getRoleName() {
        return SignSessionWithEllipticCurveDsaTest.class.getSimpleName();
    }

    private static void createEcdsaEndEntity() throws Exception {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo infoecdsa = caSession.getCAInfo(internalAdmin, TEST_ECDSA_CA_NAME);
        assertTrue("No active ECDSA CA! Must have at least one active CA to run tests!", infoecdsa != null);
        createEndEntity(ECDSA_USERNAME, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, infoecdsa.getCAId());
    }

}
