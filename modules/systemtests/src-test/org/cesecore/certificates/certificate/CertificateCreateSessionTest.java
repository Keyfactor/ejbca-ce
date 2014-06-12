/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CaTestUtils;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests creating certificate with extended key usage.
 * 
 * @version $Id$
 */
public class CertificateCreateSessionTest extends RoleUsingTestCase {

    private static KeyPair keys;
    private static final String X509CADN = "CN=CertificateCreateSessionTest";
    private CA testx509ca;

    private static CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private static RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "CertificateCreateSessionTest"));

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Before
    public void setUp() throws Exception {
        // Set up base role that can edit roles
        setUpAuthTokenAndRole("CertCreateSessionTest");

        testx509ca = CaTestUtils.createTestX509CA(X509CADN, null, false);

        // Now we have a role that can edit roles, we can edit this role to include more privileges
        RoleData role = roleAccessSession.findRole("CertCreateSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.EDITCERTIFICATEPROFILE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), CryptoTokenRules.BASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(alwaysAllowToken, role, accessRules);

        // Remove any lingering testca before starting the tests
        caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());
        // Now add the test CA so it is available in the tests
        caSession.addCA(alwaysAllowToken, testx509ca);
    }

    @After
    public void tearDown() throws Exception {
        // Remove any testca before exiting tests
        try {
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
            caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
        }
    }

    @Test
    public void test01CodeSigningExtKeyUsage() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        list.add("1.3.6.1.4.1.311.2.1.21"); // MS individual code signing
        list.add("1.3.6.1.4.1.311.2.1.22"); // MS commercial code signing
        certprof.setExtendedKeyUsage(list);
        String fingerprint = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            EndEntityInformation user = new EndEntityInformation("extkeyusagefoo", "C=SE,O=AnaTom,CN=extkeyusagefoo", testx509ca.getCAId(), null,
                    "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate cert = (X509Certificate) resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
            //log.debug("Cert=" + cert.toString());
            List<String> ku = cert.getExtendedKeyUsage();
            assertEquals(2, ku.size());
            assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.21"));
            assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.22"));

            // Check that the cert got created in the database
            Certificate cert1 = certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert));
            assertNotNull(cert1);
            assertEquals(fingerprint, CertTools.getFingerprintAsString(cert1));
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(fingerprint);
        }
    }

    @Test
    public void test02SSHExtKeyUsage() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        certprof.setExtendedKeyUsage(list);

        String fingerprint = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            EndEntityInformation user = new EndEntityInformation("extkeyusagefoo", "C=SE,O=AnaTom,CN=extkeyusagefoo", testx509ca.getCAId(), null,
                    "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate cert = (X509Certificate) resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
            //log.debug("Cert=" + cert.toString());
            List<String> ku = cert.getExtendedKeyUsage();
            assertNull(ku);
            internalCertStoreSession.removeCertificate(fingerprint);

            // Now add the SSH extended key usages
            list.add("1.3.6.1.5.5.7.3.21"); // SSH client
            list.add("1.3.6.1.5.5.7.3.22"); // SSH server
            certprof.setExtendedKeyUsage(list);
            certProfileSession.changeCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            cert = (X509Certificate) resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
            //log.debug("Cert=" + cert.toString());
            ku = cert.getExtendedKeyUsage();
            assertEquals(2, ku.size());
            assertTrue(ku.contains("1.3.6.1.5.5.7.3.21"));
            assertTrue(ku.contains("1.3.6.1.5.5.7.3.22"));

            // Check that the cert got created in the database
            Certificate cert1 = certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert));
            assertNotNull(cert1);
            assertEquals(CertTools.getFingerprintAsString(cert), CertTools.getFingerprintAsString(cert1));
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(fingerprint);
        }
    }

    @Test
    public void testDnFromRequestAllowDnOverride() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowDNOverride(false); // first test with override not allowed
        assertTrue(certprof.getUseLdapDnOrder());
        String finger1 = null;
        String finger2 = null;
        String finger3 = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            // EJBCA standard has SN means serialnumber, surname is SURNAME. Must be kept for backwards compatibility
            EndEntityInformation user = new EndEntityInformation("dnoverride", "C=SE,O=AnaTom,SN=123456,SURNAME=surname,CN=dnoverride",
                    testx509ca.getCAId(), null, "dnoverride@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), "dnoverride", "foo123");
            req.setIssuerDN(CertTools.getIssuerDN(testx509ca.getCACertificate()));
            req.setRequestDN("C=SE,O=PrimeKey,SN=123456,SURNAME=surname,CN=noUserData");

            // Make the call
            {
                X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                        org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
                assertNotNull("Failed to get response", resp);
                Certificate cert = (X509Certificate) resp.getCertificate();
                finger1 = CertTools.getFingerprintAsString(cert);
                assertNotNull("Failed to create certificate", cert);
                assertEquals("CN=dnoverride,SN=123456,SURNAME=surname,O=AnaTom,C=SE", ((X509Certificate) cert).getSubjectDN().toString());
            }
            // Make the call again, now allowing DN override
            certprof.setAllowDNOverride(true);
            certProfileSession.changeCertificateProfile(roleMgmgToken, "createCertTest", certprof);
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            Certificate cert = (X509Certificate) resp.getCertificate();
            finger2 = CertTools.getFingerprintAsString(cert);
            assertNotNull("Failed to create certificate", cert);
            assertEquals("C=SE,O=PrimeKey,SN=123456,SURNAME=surname,CN=noUserData", ((X509Certificate) cert).getSubjectDN().toString());
            // Test reversing DN, should make no difference since we override with requestDN
            certprof.setUseLdapDnOrder(false);
            certProfileSession.changeCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            cert = (X509Certificate) resp.getCertificate();
            finger3 = CertTools.getFingerprintAsString(cert);
            assertNotNull("Failed to create certificate", cert);
            assertEquals("C=SE,O=PrimeKey,SN=123456,SURNAME=surname,CN=noUserData", ((X509Certificate) cert).getSubjectDN().toString());
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(finger1);
            internalCertStoreSession.removeCertificate(finger2);
            internalCertStoreSession.removeCertificate(finger3);
        }
    }

    @Test
    public void testDnOrder() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        assertTrue(certprof.getUseLdapDnOrder());
        String finger1 = null;
        String finger2 = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            // EJBCA standard has SN means serialnumber, surname is SURNAME. Must be kept for backwards compatibility
            EndEntityInformation user = new EndEntityInformation("dnorder", "C=SE,O=PrimeKey,SN=12345,SURNAME=surname,CN=DnOrderTest",
                    testx509ca.getCAId(), null, "dnoverride@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), "dnorder", "foo123");
            req.setIssuerDN(CertTools.getIssuerDN(testx509ca.getCACertificate()));
            req.setRequestDN("C=SE,O=Foo Company,SN=12345,SURNAME=surname,CN=DnOrderTest"); // This should not matter now

            // Make the call
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            Certificate cert = (X509Certificate) resp.getCertificate();
            finger1 = CertTools.getFingerprintAsString(cert);
            assertNotNull("Failed to create certificate", cert);
            X500Principal princ = ((X509Certificate) cert).getSubjectX500Principal();
            X500Name name = X500Name.getInstance(princ.getEncoded());
            assertEquals("CN=DnOrderTest,SERIALNUMBER=12345,SURNAME=surname,O=PrimeKey,C=SE", name.toString());
            // Get device serial number to check that it really is the correct stuff and that SerialNumber and SurName has not gotten mixed up
            RDN[] rdns = name.getRDNs(new ASN1ObjectIdentifier("2.5.4.5")); // Device serial number
            assertEquals(1, rdns.length);
            AttributeTypeAndValue value = rdns[0].getFirst();
            assertEquals("12345", value.getValue().toString());
            rdns = name.getRDNs(new ASN1ObjectIdentifier("2.5.4.4")); // Surname (last name)
            value = rdns[0].getFirst();
            assertEquals(1, rdns.length);
            assertEquals("surname", value.getValue().toString());

            // Test reversing DN, should make a lot of difference
            certprof.setUseLdapDnOrder(false);
            certProfileSession.changeCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            cert = (X509Certificate) resp.getCertificate();
            finger2 = CertTools.getFingerprintAsString(cert);
            assertNotNull("Failed to create certificate", cert);
            princ = ((X509Certificate) cert).getSubjectX500Principal();
            name = X500Name.getInstance(princ.getEncoded());
            assertEquals("C=SE,O=PrimeKey,SURNAME=surname,SERIALNUMBER=12345,CN=DnOrderTest", name.toString());
            // Get device serial number to check that it really is the correct stuff and that SerialNumber and SurName has not gotten mixed up
            rdns = name.getRDNs(new ASN1ObjectIdentifier("2.5.4.5")); // Device serial number
            assertEquals(1, rdns.length);
            value = rdns[0].getFirst();
            assertEquals("12345", value.getValue().toString());
            rdns = name.getRDNs(new ASN1ObjectIdentifier("2.5.4.4")); // Surname (last name)
            value = rdns[0].getFirst();
            assertEquals(1, rdns.length);
            assertEquals("surname", value.getValue().toString());
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(finger1);
            internalCertStoreSession.removeCertificate(finger2);
        }
    }

    @Test
    public void test27IssuanceRevocationReason() throws Exception {

        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        String fp1 = null;
        String fp2 = null;
        String fp3 = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            EndEntityInformation user = new EndEntityInformation();
            user.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            user.setUsername("certcreatereq");
            user.setDN("C=SE,O=PrimeKey,CN=noUserData");
            user.setCertificateProfileId(cpId);

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), "certcreatereq", "foo123");
            req.setIssuerDN(CertTools.getIssuerDN(testx509ca.getCACertificate()));
            req.setRequestDN("C=SE,O=PrimeKey,CN=noUserData");

            // Make the call
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            Certificate cert = (X509Certificate) resp.getCertificate();
            fp1 = CertTools.getFingerprintAsString(cert);
            assertNotNull("Failed to create certificate", cert);
            assertEquals("CN=noUserData,O=PrimeKey,C=SE", CertTools.getSubjectDN(cert));
            // Check that it is active
            boolean isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertFalse(isRevoked);

            // Now add extended information with the revocation reason
            ExtendedInformation ei = new ExtendedInformation();
            ei.setIssuanceRevocationReason(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            user.setExtendedinformation(ei);
            // create cert again
            resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            Certificate cert2 = (X509Certificate) resp.getCertificate();
            fp2 = CertTools.getFingerprintAsString(cert2);
            assertFalse(fp1.equals(fp2));

            // Check that it is revoked
            isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert2), CertTools.getSerialNumber(cert2));
            assertTrue(isRevoked);
            CertificateStatus rev = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertEquals(RevokedCertInfo.NOT_REVOKED, rev.revocationReason);
            rev = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert2), CertTools.getSerialNumber(cert2));
            assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, rev.revocationReason);

            // Make the same test but have some empty fields in the DN to get ECA-1841 DNs in userdata
            user.setDN("CN=noUserData,OU=,OU=FooOU,O=PrimeKey,C=SE");
            assertEquals("CN=noUserData,OU=,OU=FooOU,O=PrimeKey,C=SE", user.getDN());
            assertEquals("CN=noUserData,OU=FooOU,O=PrimeKey,C=SE", user.getCertificateDN());
            // Create cert again
            resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to get response", resp);
            Certificate cert3 = (X509Certificate) resp.getCertificate();
            assertNotNull("Failed to create cert", cert3);
            fp3 = CertTools.getFingerprintAsString(cert3);
            assertEquals(user.getCertificateDN(), CertTools.getSubjectDN(cert3));
            // Check that it is revoked
            isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert3), CertTools.getSerialNumber(cert3));
            assertTrue(isRevoked);
            rev = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert3), CertTools.getSerialNumber(cert3));
            assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, rev.revocationReason);

        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
            internalCertStoreSession.removeCertificate(fp3);
        }
    }

    @Test
    public void test38UniqueSubjectDN() throws Exception {
        // Make sure that the CA requires unique subject DN
        CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
        boolean enforceuniquesubjectdn = cainfo.isDoEnforceUniqueDistinguishedName();
        // We don't want to use this for simplicity of the test
        boolean enforceuniquekey = cainfo.isDoEnforceUniquePublicKeys();
        cainfo.setDoEnforceUniqueDistinguishedName(true);
        cainfo.setDoEnforceUniquePublicKeys(false);
        String fp1 = null;
        String fp2 = null;
        try {
            caSession.editCA(roleMgmgToken, cainfo);

            // Change already existing user
            EndEntityInformation user1 = new EndEntityInformation();
            user1.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            user1.setUsername("unique1");
            user1.setDN("CN=foounique,O=PrimeKey,C=SE");
            user1.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            EndEntityInformation user2 = new EndEntityInformation();
            user2.setType(EndEntityTypes.ENDUSER.toEndEntityType());
            user2.setUsername("unique2");
            user2.setDN("CN=foounique,O=PrimeKey,C=SE");
            user2.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            // create first cert
            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), "certcreatereq", "foo123");
            req.setIssuerDN(CertTools.getIssuerDN(testx509ca.getCACertificate()));
            req.setRequestDN("CN=foounique,O=PrimeKey,C=SE");
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user1, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to create cert", resp);
            fp1 = CertTools.getFingerprintAsString(resp.getCertificate());
            // Create second cert, should not work with the same DN
            try {
                resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user2, req,
                        org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
                assertTrue("Should not work to create same DN with another username", false);
            } catch (CesecoreException e) {
                assertEquals(ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER, e.getErrorCode());
            }

            // Make the same test but have some empty fields in the DN to get ECA-1841 DNs in userdata
            // Set a different DN, EJBCA should detect this as "non unique DN" even though there is an empty OU=
            user1.setDN("CN=foounique,OU=,OU=FooOU,O=PrimeKey,C=SE");
            assertEquals("CN=foounique,OU=,OU=FooOU,O=PrimeKey,C=SE", user1.getDN());
            assertEquals("CN=foounique,OU=FooOU,O=PrimeKey,C=SE", user1.getCertificateDN());
            // Create cert again, should work now, first time with unique DN
            resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user1, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Failed to create cert", resp);
            fp2 = CertTools.getFingerprintAsString(resp.getCertificate());
            // Now the second user, should not work to issue the cert with the same DN
            user2.setDN("CN=foounique,OU=,OU=FooOU,O=PrimeKey,C=SE");
            assertEquals("CN=foounique,OU=,OU=FooOU,O=PrimeKey,C=SE", user2.getDN());
            assertEquals("CN=foounique,OU=FooOU,O=PrimeKey,C=SE", user2.getCertificateDN());
            // Create cert again
            try {
                resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user2, req,
                        org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
                assertTrue("Should not work to create same DN with another username", false);
            } catch (CesecoreException e) {
                assertEquals(ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER, e.getErrorCode());
            }
        } finally {
            // Finally configure the CA as it was before the test
            cainfo.setDoEnforceUniqueDistinguishedName(enforceuniquesubjectdn);
            cainfo.setDoEnforceUniquePublicKeys(enforceuniquekey);
            caSession.editCA(roleMgmgToken, cainfo);
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
        }
    }

    @Test
    public void testInvalidSignatureAlg() throws CertificateProfileExistsException, AuthorizationDeniedException,
            CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException, CertificateCreateException,
            CryptoTokenOfflineException, SignRequestSignatureException, IllegalNameException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, CertificateExtensionException {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setSignatureAlgorithm("MD5WithRSA");
        //Make sure that certificate doesn't already exist in database.
        final String username = "signalgtest";
        for (Certificate certificate : certificateStoreSession.findCertificatesByUsernameAndStatus(username, EndEntityConstants.STATUS_NEW)) {
            internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(certificate));
        }
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);
            EndEntityInformation user = new EndEntityInformation(username, "C=SE,O=PrimeKey,CN=signalgtest", testx509ca.getCAId(), null,
                    "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            try {
                certificateCreateSession.createCertificate(roleMgmgToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams());
                fail("Creating certificate should not work with invalid signature algoritmh,");
            } catch (InvalidAlgorithmException e) {
                //Expected state, make sure rollback occurred
                assertEquals("Certificate was created in spite of invalid signature algorithm", 0, certificateStoreSession
                        .findCertificatesByUsernameAndStatus(username, EndEntityConstants.STATUS_NEW).size());
            }
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            for (Certificate certificate : certificateStoreSession.findCertificatesByUsernameAndStatus(username, EndEntityConstants.STATUS_NEW)) {
                internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(certificate));
            }
        }
    }

    @Test
    public void testNullInjection() throws Exception {
        // Make sure that the CA requires unique subject DN, but not unique public keys
        CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
        boolean enforceuniquesubjectdn = cainfo.isDoEnforceUniqueDistinguishedName();
        boolean enforceuniquekey = cainfo.isDoEnforceUniquePublicKeys();
        cainfo.setDoEnforceUniqueDistinguishedName(true);
        cainfo.setDoEnforceUniquePublicKeys(false);
        caSession.editCA(roleMgmgToken, cainfo);
        // Use certificate profile that allows DN override
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowDNOverride(true);
        String fp1 = null;
        String fp2 = null;
        String fp3 = null;
        String fp4 = null;
        String fp5 = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);
            EndEntityInformation user = new EndEntityInformation("null\0injecttest", "C=SE,O=PrimeKey,CN=null\0inject%00test", testx509ca.getCAId(),
                    null, "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            try {
                X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                        X509ResponseMessage.class, signSession.fetchCertGenParams());
                X509Certificate cert = (X509Certificate) resp.getCertificate();
                fp1 = CertTools.getFingerprintAsString(cert);
                fail("We should not have been allowed to create certificate with that DN.");
            } catch (IllegalNameException e) {
                // NOPMD: This is correct and we ignore it 
            }
            try {
                // Test by passing it to requestX509Name instead
                final String requestName = "CN=another\0nullguy%00";
                req.setRequestDN(requestName);
                X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                        X509ResponseMessage.class, signSession.fetchCertGenParams());
                X509Certificate cert = (X509Certificate) resp.getCertificate();
                fp2 = CertTools.getFingerprintAsString(cert);
                fail("We should not have been allowed to create certificate with that DN.");
            } catch (IllegalNameException e) {
                // NOPMD: This is correct and we ignore it 
            }
            try {
                // Test with an escaped %, escaping % is not allowed
                final String requestName = "CN=anothernullguy\\\\%00";
                req.setRequestDN(requestName);
                X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                        X509ResponseMessage.class, signSession.fetchCertGenParams());
                X509Certificate cert = (X509Certificate) resp.getCertificate();
                fp3 = CertTools.getFingerprintAsString(cert);
                fail("We should not have been allowed to create certificate with that DN.");
            } catch (IllegalNameException e) {
                // NOPMD: This is correct and we ignore it 
            }
            try {
                // Test with a semicolon, not allowed per se, but for requestX509Name it is escaped automatically
                final String requestName = "CN=anothersemicolon;guy";
                req.setRequestDN(requestName);
                X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                        X509ResponseMessage.class, signSession.fetchCertGenParams());
                X509Certificate cert = (X509Certificate) resp.getCertificate();
                fp4 = CertTools.getFingerprintAsString(cert);
                assertEquals("Escaped semicolon should have worked", "CN=anothersemicolon\\;guy", cert.getSubjectDN().toString());
                CertificateInfo info = certificateStoreSession.getCertificateInfo(fp4);
                assertEquals("Escaped semicolon should have worked", "CN=anothersemicolon\\;guy", info.getSubjectDN());
            } catch (IllegalNameException e) {
                fail("We should have been allowed to create certificate with that DN.");
            }
            try {
                // Test with an escaped semicolon, this is allowed
                final String requestName = "CN=anothersemicolon\\;guy";
                req.setRequestDN(requestName);
                X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                        X509ResponseMessage.class, signSession.fetchCertGenParams());
                X509Certificate cert = (X509Certificate) resp.getCertificate();
                fp5 = CertTools.getFingerprintAsString(cert);
                assertEquals("Escaped semicolon should have worked", "CN=anothersemicolon\\;guy", cert.getSubjectDN().toString());
                CertificateInfo info = certificateStoreSession.getCertificateInfo(fp5);
                assertEquals("Escaped semicolon should have worked", "CN=anothersemicolon\\;guy", info.getSubjectDN());
            } catch (IllegalNameException e) {
                fail("We should have been allowed to create certificate with that DN.");
            }

        } finally {
            cainfo.setDoEnforceUniqueDistinguishedName(enforceuniquesubjectdn);
            cainfo.setDoEnforceUniquePublicKeys(enforceuniquekey);
            caSession.editCA(roleMgmgToken, cainfo);
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
            internalCertStoreSession.removeCertificate(fp3);
            internalCertStoreSession.removeCertificate(fp4);
            internalCertStoreSession.removeCertificate(fp4);
            internalCertStoreSession.removeCertificate(fp5);
        }
    }

    @Test
    public void testXssInjection() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowDNOverride(true);
        String fp1 = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);
            EndEntityInformation user = new EndEntityInformation("<script>foo</script>", "CN=<script>alert('cesecore')</script>",
                    testx509ca.getCAId(), null, "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, cpId,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate cert = (X509Certificate) resp.getCertificate();
            fp1 = CertTools.getFingerprintAsString(cert);
            assertEquals("The DN should have escaped < and >", "CN=\\<script\\>alert('cesecore')\\</script\\>", cert.getSubjectDN().toString());
        } finally {
            certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
            internalCertStoreSession.removeCertificate(fp1);
        }
    }

    /** A PKCS#10 request with corrupt public key record, the public key asn.1 "sequence" has been hexedited */
    private static byte[] invalidp10 = Base64.decode(("MIH0MIGfAgEAMDwxCzAJBgNVBAYTAlNFMREwDwYDVQQKDAhQcmltZUtleTEaMBgG"
            + "A1UEAwwRcGtjczEwcmVxdWVzdHRlc3QwXDANBgkqhkiG9w0BAQEFAANLAP///0EA" + "lZdRWN6AfWzPggOBeqsX7rMxqHeSH+UhLhq+UjJ+ULizWmKtTAj5BmoLTN81DLS7"
            + "Vgx//q+Z3ag6llYJclWaWwIDAQABMA0GCSqGSIb3DQEBBQUAA0EAPWa7h5tZF+4x" + "2n8pDGhxbiJmUzFUlXgdUBRpstId0DZ6sWGzSnCPDEnPgsR95qVpYiP+V4vWV2Hu"
            + "KNIGAvdeeQ==").getBytes());

    @Test
    public void testPKCS10Request() throws Exception {
        String fp1 = null;
        try {
            final String dn = "C=SE,O=PrimeKey,CN=pkcs10requesttest";
            final EndEntityInformation user = new EndEntityInformation("pkcs10requesttest", dn, testx509ca.getCAId(), null, "foo@anatom.se",
                    new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);

            final KeyPair keyPair = KeyTools.genKeys("512", "RSA");
            final X500Name x509dn = new X500Name(dn);
            PKCS10CertificationRequest basicpkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", x509dn, keyPair.getPublic(), null,
                    keyPair.getPrivate(), null);
            ContentVerifierProvider cvp = CertTools.genContentVerifierProvider(keyPair.getPublic());
            assertTrue("Request must verify (POP)", basicpkcs10.isSignatureValid(cvp));
            PKCS10RequestMessage req = new PKCS10RequestMessage(basicpkcs10.toASN1Structure().getEncoded());
            assertTrue("Request must verify (POP)", req.verify());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    X509ResponseMessage.class, signSession.fetchCertGenParams());
            assertNotNull("Creating a cert should have worked", resp);
            X509Certificate cert = (X509Certificate) resp.getCertificate();
            fp1 = CertTools.getFingerprintAsString(cert);

            // Create a request with invalid PoP
            final KeyPair keyPair2 = KeyTools.genKeys("512", "RSA");
            PKCS10CertificationRequest invalidpoppkcs10 = CertTools.genPKCS10CertificationRequest("SHA256WithRSA", x509dn, keyPair.getPublic(), null,
                    keyPair2.getPrivate(), null);
            req = new PKCS10RequestMessage(invalidpoppkcs10.toASN1Structure().getEncoded());
            try {
                resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams());
                fail("Creating a cert from a request with invalid PoP (proof of possession) should not work");
            } catch (SignRequestSignatureException e) {
                // NOPMD: this is what we want
            }

            // Try with a PKCS#10 request with a asn.1 corrupt public key entry
            req = new PKCS10RequestMessage(invalidp10);
            try {
                resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams());
                fail("Creating a cert from a request with invalid PoP (proof of possession) should not work");
            } catch (IllegalKeyException e) { // NOPMD: this is what we want
            } catch (SignRequestSignatureException e) {
            } // NOPMD: or this depending on BC version etc

        } finally {
            internalCertStoreSession.removeCertificate(fp1);
        }
    }

    @Test
    public void testAuthorization() throws Exception {

        // AuthenticationToken that does not have privileges to create a certificate
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CertProfileSessionNoAuth", 365, null, keys.getPrivate(),
                keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);

        EndEntityInformation user = new EndEntityInformation("certcreateauth", "C=SE,O=AnaTom,CN=certcreateauth", testx509ca.getCAId(), null,
                "foo@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");

        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());

        String fingerprint = null;
        try {
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(adminTokenNoAuth, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate cert = (X509Certificate) resp.getCertificate();
            fingerprint = CertTools.getFingerprintAsString(cert);
            assertTrue("should throw", false);
        } catch (AuthorizationDeniedException e) {
            // NOPMD
        } finally {
            internalCertStoreSession.removeCertificate(fingerprint);
        }
    }

}
