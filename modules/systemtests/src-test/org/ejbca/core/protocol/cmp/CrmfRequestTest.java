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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.Arrays;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test runs in CMP client mode.
 *
 * You can run this test against a CMP Proxy instead of directly to the CA by setting the system property httpCmpProxyURL,
 * for example "-DhttpCmpProxyURL=http://proxy-ip:8080/cmpProxy-6.4.0", which can be set in Run Configurations if running the
 * test from Eclipse.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CrmfRequestTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRequestTest.class);

    private static final String USER = "abc123rry" + new Random().nextLong();
    private final static X500Name USER_DN = new X500Name("CN=" + USER + ", O=PrimeKey Solutions AB, C=SE");
    private final static String ISSUER_DN = "CN=TestCA";
    private final KeyPair keys;
    private final int caid;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private final static String cmpAlias = "CrmfRequestTestCmpConfigAlias";

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    public CrmfRequestTest() throws Exception {
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        this.testx509ca = CaTestUtils.createTestX509CA(ISSUER_DN, null, false, keyusage);
        this.caid = this.testx509ca.getCAId();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
        this.keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        this.caSession.addCA(ADMIN, this.testx509ca);
        log.debug("ISSUER_DN: " + ISSUER_DN);
        log.debug("caid: " + this.caid);
        this.cmpConfiguration.addAlias(cmpAlias);
        this.cmpConfiguration.setRAMode(cmpAlias, false);
        this.cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        this.cmpConfiguration.setCMPDefaultCA(cmpAlias, ISSUER_DN);
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;foo123");
        this.cmpConfiguration.setExtractUsernameComponent(cmpAlias, "CN");
        this.cmpConfiguration.setRACertProfile(cmpAlias, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRAEEProfile(cmpAlias, String.valueOf(eepDnOverrideId));
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        CryptoTokenTestUtils.removeCryptoToken(null, this.testx509ca.getCAToken().getCryptoTokenId());
        this.caSession.removeCA(ADMIN, this.caid);
        try {
            this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
        } catch (NoSuchEndEntityException e) {
            // A test probably failed before creating the entity
            log.debug("Failed to delete USER \"cmptest\".");
        }
        this.cmpConfiguration.removeAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void test01CrmfHttpUnknowUser() throws Exception {
        log.trace(">test01CrmfHttpUnknowUser");
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        // USER_DN = USER_DN + ", serialNumber=01234567";
        PKIMessage req = genCertReq(ISSUER_DN, USER_DN, this.keys, this.cacert, nonce, transid, false, null, new Date(), new Date(), null, null, null);
        assertNotNull(req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, ISSUER_DN, USER_DN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        // Expect a CertificateResponse (reject) message with error FailInfo.INCORRECT_DATA
        checkCmpFailMessage(resp, "Wrong username or password", 1, reqId, 7, PKIFailureInfo.incorrectData);
        log.trace("<test01CrmfHttpUnknowUser");
    }

    @Test
    public void test02CrmfHttpUnknowUserSignedMessage() throws Exception {
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        PKIMessage req = genCertReq(ISSUER_DN, USER_DN, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull(req);
        X509Certificate signCert = CertTools.genSelfCert("CN=CMP Sign Test", 3650, null, this.keys.getPrivate(), this.keys.getPublic(), "SHA256WithRSA", false);
        ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signCert);
        CmpMessageHelper.signPKIMessage(req, signCertColl, this.keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1, BouncyCastleProvider.PROVIDER_NAME);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, ISSUER_DN, USER_DN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        // Expect a CertificateResponse (reject) message with error FailInfo.INCORRECT_DATA
        checkCmpFailMessage(resp, "Wrong username or password", 1, reqId, 7, PKIFailureInfo.incorrectData);
    }

    @Test
    public void test03CrmfHttpOkUser() throws Exception {
        log.trace(">test03CrmfHttpOkUser");
        // Create a new good USER
        X500Name userDN = createCmpUser("cmptest", "foo123", "C=SE,O=PrimeKey,CN=cmptest", true, this.caid, -1, -1);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genCertReq(ISSUER_DN, userDN, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null);
        assertNotNull(req);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertNull("AltNames was not null (" + altNames + ").", altNames);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, reqId);
        ba = CmpMessageHelper.pkiMessageToByteArray(confirm);
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        // Now revoke the bastard!
        PKIMessage rev = genRevReq(ISSUER_DN, userDN, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
        byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
        // Send request and receive response
        resp = sendCmpHttp(barev, 200, cmpAlias);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpFailMessage(resp, "PKI Message is not authenticated properly. No HMAC protection was found.", PKIBody.TYPE_ERROR, reqId,
                                PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);

        //
        // Try again, this time setting implicitConfirm in the header, expecting the server to reply with implicitConfirm as well
        userDN = createCmpUser("cmptest", "foo123", "C=SE,O=PrimeKey,CN=cmptest", true, this.caid, -1, -1);
        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();
        DEROctetString keyId = new DEROctetString("primekey".getBytes());
        req = genCertReq(ISSUER_DN, userDN, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, keyId, true);
        assertNotNull(req);
        ir = (CertReqMessages) req.getBody().getContent();
        reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), true, "primekey");
        cert = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
        altNames = CertTools.getSubjectAlternativeName(cert);
        assertNull("AltNames was not null (" + altNames + ").", altNames);

        log.trace("<test03CrmfHttpOkUser");
    }

    @Test
    public void test04BlueXCrmf() throws Exception {
        log.trace(">test04BlueXCrmf");
        // An EE with a matching subject and clear text password set to "foo123" must exist for HMAC validation in this test.
        // foo123 is not the correct password however, so we will fail HMAC verification
        final String username = "Some Common Name";
        try {
            super.createCmpUser(username, "password", "CN=Some Common Name", false, this.caid, -1, -1);
            byte[] resp = sendCmpHttp(bluexir, 200, cmpAlias);
            assertNotNull(resp);
            // In this very old BlueX message, POP verification fails. 
            // The HMAC password used to protect the request is 'password', which is set on the CMP user "Some Common Name" above
            checkCmpPKIErrorMessage(resp, "C=NL,O=A.E.T. Europe B.V.,OU=Development,CN=Test CA 1", new X500Name(new RDN[0]), PKIFailureInfo.badPOP, null); // expecting a bad_pop
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, username);        	
        }

        try {
            super.createCmpUser(username, "foo123", "CN=Some Common Name", false, this.caid, -1, -1);
            byte[] resp = sendCmpHttp(bluexir, 200, cmpAlias);
            assertNotNull(resp);
            // If we don't know the HMAC password, the below error will be instead
            checkCmpPKIErrorMessage(resp, "C=NL,O=A.E.T. Europe B.V.,OU=Development,CN=Test CA 1", new X500Name(new RDN[0]), PKIFailureInfo.badRequest, null); // expecting a bad_pop
        } finally {
            endEntityManagementSession.deleteUser(ADMIN, username);         
        }

        log.trace("<test04BlueXCrmf");
    }

    @Test
    public void test05BadBytes() throws Exception {
        log.trace(">test05BadBytes");
        byte[] msg = bluexir;
        // Change some bytes to make the message bad
        msg[10] = 0;
        msg[15] = 0;
        msg[22] = 0;
        msg[56] = 0;
        msg[88] = 0;
        /* Before EJBCA 6.8.0 we responded with HTTP 400, but now we send a PKIFailureInfo.badRequest instead. */
        byte[] resp = sendCmpHttp(msg, 200, cmpAlias);
        assertNotNull(resp);
        checkCmpFailMessage(resp, "Not a valid CMP message.", PKIBody.TYPE_ERROR, 123, PKIFailureInfo.badRequest, PKIFailureInfo.incorrectData);
        log.trace("<test05BadBytes");
    }

    @Test
    public void test07SignedConfirmationMessage() throws Exception {
        log.trace(">test07SignedConfirmationMessage()");
        CmpConfirmResponseMessage cmpConfRes = new CmpConfirmResponseMessage();
        cmpConfRes.setSignKeyInfo(this.testx509ca.getCertificateChain(), this.keys.getPrivate(), null);
        cmpConfRes.setSender(new GeneralName(USER_DN));
        cmpConfRes.setRecipient(new GeneralName(new X500Name("CN=cmpRecipient, O=TEST")));
        cmpConfRes.setSenderNonce("DAxFSkJDQSBTYW==");
        cmpConfRes.setRecipientNonce("DAxFSkJDQSBTYY==");
        cmpConfRes.setTransactionId("MTMzNwo=");
        cmpConfRes.create();
        byte[] resp = cmpConfRes.getResponseMessage();
        PKIMessage msg = PKIMessage.getInstance(ASN1Primitive.fromByteArray(resp));
        boolean veriStatus = CmpMessageHelper.verifyCertBasedPKIProtection(msg, this.keys.getPublic());
        assertTrue("Verification failed.", veriStatus);
        log.trace("<test07SignedConfirmationMessage()");
    }

    @Test
    public void testUnsignedConfirmationMessage() throws Exception {
        log.trace(">testUnsignedConfirmationMessage()");
        CmpConfirmResponseMessage cmpConfRes = new CmpConfirmResponseMessage();
        //cmpConfRes.setSignKeyInfo(this.testx509ca.getCertificateChain(), this.keys.getPrivate(), null);
        cmpConfRes.setSender(new GeneralName(USER_DN));
        cmpConfRes.setRecipient(new GeneralName(new X500Name("CN=cmpRecipient, O=TEST")));
        cmpConfRes.setSenderNonce("DAxFSkJDQSBTYW==");
        cmpConfRes.setRecipientNonce("DAxFSkJDQSBTYY==");
        cmpConfRes.setTransactionId("MTMzNwo=");
        cmpConfRes.create();
        byte[] resp = cmpConfRes.getResponseMessage();
        PKIMessage msg = PKIMessage.getInstance(ASN1Primitive.fromByteArray(resp));
        try {
            CmpMessageHelper.verifyCertBasedPKIProtection(msg, this.keys.getPublic());
            fail("Attempting to verify signature on an unsigned message should have failed.");
        } catch (SignatureException e) {
            log.debug("Expected exception: " + e.getMessage());
        }
        log.trace("<testUnsignedConfirmationMessage()");
    }

    @Test
    public void test08SubjectDNSerialnumber() throws Exception {
        log.trace(">test08SubjectDNSerialnumber");
        // Create a new good USER
        String cmpsntestUsername = "cmpsntest";
        String cmpsntest2Username = "cmpsntest2";
        final X500Name userDN1 = createCmpUser(cmpsntestUsername, "foo123", "C=SE,SN=12234567,CN=cmpsntest", true, this.caid, -1, -1);

        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            PKIMessage req = genCertReq(ISSUER_DN, userDN1, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN1, this.cacert, resp, reqId);

            // Now revoke the certificate!
            PKIMessage rev = genRevReq(ISSUER_DN, userDN1, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            assertNotNull(rev);
            byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200,cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(ISSUER_DN, CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);

            // Create another USER with the subjectDN serialnumber spelled "SERIALNUMBER" instead of "SN"
            KeyPair keys2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            final X500Name userDN2 = createCmpUser(cmpsntest2Username, "foo123", "C=SE,SERIALNUMBER=123456789,CN=cmpsntest2", true, this.caid, -1, -1);
            req = genCertReq(ISSUER_DN, userDN2, keys2, this.cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN2, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            cert = checkCmpCertRepMessage(userDN2, this.cacert, resp, reqId);

            // Now revoke this certificate too
            rev = genRevReq(ISSUER_DN, userDN2, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            assertNotNull(rev);
            barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN2, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            revStatus = checkRevokeStatus(ISSUER_DN, CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            this.endEntityManagementSession.deleteUser(ADMIN, cmpsntestUsername);
            this.endEntityManagementSession.deleteUser(ADMIN, cmpsntest2Username);
        }
        log.trace("<test08SubjectDNSerialnumber");
    }

    @Test
    public void test09KeyIdTest() {
        log.trace(">test09KeyIdTest()");
        DEROctetString octs = new DEROctetString("foo123".getBytes());
        String keyid = CmpMessageHelper.getStringFromOctets(octs);
        assertEquals("foo123", keyid);

        PKIHeaderBuilder headerbuilder = new PKIHeaderBuilder(PKIHeader.CMP_2000, new GeneralName(new X500Name("CN=Sender")), new GeneralName(new X500Name("CN=Recipient")));
        headerbuilder.setSenderKID(new DEROctetString("foo123".getBytes()));
        PKIHeader header = headerbuilder.build();
        keyid = CmpMessageHelper.getStringFromOctets(header.getSenderKID());
        assertEquals("foo123", keyid);
        log.trace("<test09KeyIdTest()");
    }

    @Test
    public void test10EscapedCharsInDN() throws Exception {
        log.trace(">test10EscapedCharsInDN");

        this.cmpConfiguration.setExtractUsernameComponent(cmpAlias, "DN");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // --------------- Send a CRMF request with the whole DN as username with escapable characters --------------- //
        final String sRequestName = "CN=another\0nullguy%00<do>";
        // Create a new good USER
        final X500Name requestName = createCmpUser(sRequestName, "foo123", sRequestName, false, this.caid, -1, -1);

        try {
            PKIMessage req = genCertReq(ISSUER_DN, requestName, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, requestName, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(new X500Name(StringTools.strip(sRequestName)), this.cacert, resp, reqId);
            assertNotNull(cert);

            // Now revoke the bastard!
            PKIMessage rev = genRevReq(ISSUER_DN, requestName, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, requestName, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(ISSUER_DN, CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            String escapedName = StringTools.stripUsername(sRequestName);
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, escapedName);
            } catch (NoSuchEndEntityException e) {
                // A test probably failed before creating the entity
                log.debug("Failed to delete USER: " + escapedName);
            }
        }

        // --------------- Send a CRMF request with a username with escapable characters --------------- //
        final String username = "another\0nullguy%00";
        final String sDN = "CN=" + username + ", C=SE, O=hejsan";
        KeyPair key2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

        // Create a new good USER
        final X500Name dn = createCmpUser(username, "foo123", sDN, false, this.caid, -1, -1);

        try {
            PKIMessage req = genCertReq(ISSUER_DN, dn, key2, this.cacert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, dn, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(dn, this.cacert, resp, reqId);
            assertNotNull(cert);

            // Now revoke the bastard!
            PKIMessage rev = genRevReq(ISSUER_DN, dn, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, cmpAlias);
            checkCmpResponseGeneral(resp, ISSUER_DN, dn, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            int revStatus = checkRevokeStatus(ISSUER_DN, CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            String escapedName = StringTools.strip(username);
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, escapedName);
            } catch (NoSuchEndEntityException e) {
                // A test probably failed before creating the entity
                log.debug("Failed to delete USER: " + escapedName);
            }
        }
        log.trace("<test10EscapedCharsInDN");
    }

    @Test
    public void  test11IncludingCertChainInSignedCMPResponse() throws Exception {
        //---------- Create SubCA signed by testx509ca (rootCA) ------------- //
        String subcaDN = "CN=SubTestCA";
        int subcaID = subcaDN.hashCode();
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(ADMIN, null, true, false, subcaDN, "1024");
        final String username = "cmptest";
        try {
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
            final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<ExtendedCAServiceInfo>(2);
            extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            String caname = CertTools.getPartFromDN(subcaDN, "CN");
            boolean ldapOrder = !CertTools.isDNReversed(subcaDN);
            X509CAInfo cainfo = new X509CAInfo(subcaDN, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA,
                    "3650d", this.caid, this.testx509ca.getCertificateChain(), catoken);
            cainfo.setDescription("JUnit RSA SubCA");
            cainfo.setExtendedCAServiceInfos(extendedCaServices);
            cainfo.setUseLdapDnOrder(ldapOrder);
            cainfo.setCmpRaAuthSecret("foo123");

            CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
            caAdminSession.createCA(ADMIN, cainfo);
            assertTrue(this.caSession.existsCa(subcaID));
            cainfo = (X509CAInfo) this.caSession.getCAInfo(ADMIN, subcaID);
            X509Certificate subcaCert = (X509Certificate) cainfo.getCertificateChain().iterator().next();

            // --------- Create a user ----------------- //
            final X500Name userDN = new X500Name("C=SE,O=PrimeKey,CN=cmptest");
            EndEntityInformation user = new EndEntityInformation("cmptest", userDN.toString(), subcaID,
                    null, "cmptest@primekey.se", new EndEntityType(EndEntityTypes.ENDUSER),
//                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    this.eepDnOverrideId, this.cpDnOverrideId,
                    SecConst.TOKEN_SOFT_PEM, 0, null);
            user.setPassword("foo123");
            try {
                this.endEntityManagementSession.addUser(ADMIN, user, true);
                log.debug("created user: cmptest, foo123, " + userDN);
            } catch (EndEntityExistsException e) {
                log.debug("User cmptest already exists.");
                this.endEntityManagementSession.changeUser(ADMIN, user, true);
                this.endEntityManagementSession.setUserStatus(ADMIN, "cmptest", EndEntityConstants.STATUS_NEW);
                log.debug("Reset status to NEW");
            }

            assertTrue(this.endEntityManagementSession.existsUser("cmptest"));
            EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
            EndEntityInformation ee = eeAccessSession.findUser(ADMIN, "cmptest");
            assertEquals(subcaID, ee.getCAId());

            // -------- generate and send a CMP request -------------- //
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            PKIMessage req = genCertReq(subcaDN, userDN, this.keys, subcaCert, nonce, transid, false, null, null, null, null, null, null);
            assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            checkCmpResponseGeneral(resp, subcaDN, userDN, subcaCert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            final X509Certificate cert = checkCmpCertRepMessage(userDN, subcaCert, resp, reqId);
            assertNotNull(cert);

            // ------- Check that the entire certificate chain is in the extraCerts field in the response
            PKIMessage respMsg = PKIMessage.getInstance(resp);
            assertNotNull(respMsg);

            CMPCertificate[] certChain = respMsg.getExtraCerts();
            assertEquals(2, certChain.length);
            assertEquals(subcaDN, certChain[0].getX509v3PKCert().getSubject().toString());
            assertEquals(ISSUER_DN, certChain[1].getX509v3PKCert().getSubject().toString());
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, username);
            } catch (NoSuchEndEntityException e) {
                // A test probably failed before creating the entity
                log.debug("Failed to delete user: " + username);
            }
            CryptoTokenTestUtils.removeCryptoToken(null, cryptoTokenId);
            // Remove CA certificate of CA that we will remove
            Collection<Certificate> certs = this.caSession.getCAInfo(ADMIN, subcaID).getCertificateChain();
            this.internalCertStoreSession.removeCertificate(certs.iterator().next());
            // Remove the CA itself
            this.caSession.removeCA(ADMIN, subcaID);
        }
    }

    /** Tests server generated keys, which are requested by sending a missing request public key in the CRMF request
     * message, or a SubjectPublicKeyInfo with AlgorithmId but not key bits, as specified in:
     * RFC4210 section 5.3.4 and Appendix D.4, RFC4211 Section 6.6 and Appendix B
     */
    @Test
    public void test12ServerGeneratedKeys() throws Exception {
        log.trace(">test12ServerGeneratedKeys");
        // Create a new good USER
        final String cmptestUsername = "cmpsrvgentest";
        //final String cmptestCPName = "CMPSRVGENTEST";
        final String cmptestCPName = CP_DN_OVERRIDE_NAME;
        CertificateProfile certificateProfile = this.certProfileSession.getCertificateProfile(CP_DN_OVERRIDE_NAME);
        assertNotNull(certificateProfile);
        // Backup the certificate profile so we can restore it afterwards, because we will modify it in this test
        //      certificateProfile.setAvailableBitLengths(new int[] {1024, 2048});
        //      certificateProfile.setAvailableKeyAlgorithms(new String[]{"RSA", "ECDSA"});
        CertificateProfile backup = certificateProfile.clone();
        final int cpID = certProfileSession.getCertificateProfileId(CP_DN_OVERRIDE_NAME);
        final int eepID = endEntityProfileSession.getEndEntityProfileId(EEP_DN_OVERRIDE_NAME);
        log.info("Using Certificate Profile with ID: "+cpID);
        final X500Name userDN1 = createCmpUser(cmptestUsername, "foo123", "C=SE,O=MemyselfandI,CN="+cmptestUsername, false, this.caid, eepID, cpID);
        String fingerprint1 = null;
        String fingerprint2 = null;
        String fingerprint3 = null;
        String fingerprint4 = null;
        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            // 0.

            // Send a CMP request with empty public key, signaling server key generation, but where server key generation is not allowed (the default) in the CMP alias
            // Should fail
            AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
            PKIMessage req = genCertReq(ISSUER_DN, userDN1, /*keys*/null, this.cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull(req);
            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
            // This request should fail because we did not provide a protocolEncrKey key
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "Server generated keys not allowed");
            // checkCmpFailMessage(resp, "Request public key can not be empty without providing a protocolEncrKey", 1, reqId, 7, PKIFailureInfo.badRequest);

            // 1.

            // Send a CMP request with empty public key, signaling server key generation, but where there is no protoclEncrKey to encrypt the response with
            // Should fail
            // Allow server key generation in the CMP alias
            this.cmpConfiguration.setAllowServerGeneratedKeys(cmpAlias, true);
            this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
            pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
            req = genCertReq(ISSUER_DN, userDN1, /*keys*/null, this.cacert, nonce, transid, false, null, null, null, null, pAlg, null);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // This request should fail because we did not provide a protocolEncrKey key
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "Request public key can not be empty without providing a suitable protocolEncrKey (RSA)");
            // checkCmpFailMessage(resp, "Request public key can not be empty without providing a protocolEncrKey", 1, reqId, 7, PKIFailureInfo.badRequest);

            // 2.

            // Add protocolEncKey that is not an RSA key, this will return an error as well
            KeyPair protocolEncKey = KeyTools.genKeys("secp256r1", "ECDSA");
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, null, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "Request public key can not be empty without providing a suitable protocolEncrKey (RSA)");

            // 3.

            // Add protocolEncrKey or the correct type (RSA), but have request public key null, and not a single choice of keys in the Certificate Profile, should fail
            // Sending null means that the server should choose the keytype and size allowed by the certificate profile
            protocolEncKey = KeyTools.genKeys("1024", "RSA");
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, null, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "Certificate profile specified more than one key algoritm, not possible to server generate keys");

            // 4.

            // Set a single selection in the Certificate Profile and expect a good answer
            // Sending null means that the server should choose the keytype and size allowed by the certificate profile
            certificateProfile.setAvailableBitLengths(new int[] {1024});
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"RSA"});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, null, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Now we should have a cert response
            PKIMessage pkiMessage = checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
            X509Certificate cert = checkCmpCertRepMessage(userDN1, this.cacert, resp, reqId);
            assertNotNull(cert);
            fingerprint1 = CertTools.getFingerprintAsString(cert);
            // We should also have a private key in the response
            {
                final PKIBody pkiBody = pkiMessage.getBody();
                final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
                final CertResponse certResponse = certRepMessage.getResponse()[0];
                final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
                // certifiedKeyPair.getCertOrEncCert().getCertificate() is what we verified above in checkCmpCertRepMessage
                // Now lets try to dig out the encrypted private key
                // Created from:
                // JcaEncryptedValueBuilder encBldr = new JcaEncryptedValueBuilder(
                //   new JceAsymmetricKeyWrapper(protocolEncrKey).setProvider(BouncyCastleProvider.PROVIDER_NAME),
                //   new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build());
                // myCertifiedKeyPair = new CertifiedKeyPair(retCert, encBldr.build(kp.getPrivate()), null);
                EncryptedValue encValue = certifiedKeyPair.getPrivateKey();
                AsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(encValue.getKeyAlg(), protocolEncKey.getPrivate());
                byte[] secKeyBytes = (byte[])unwrapper.generateUnwrappedKey(encValue.getKeyAlg(), encValue.getEncSymmKey().getBytes()).getRepresentation();
                // recover private key
                PKCS8EncryptedPrivateKeyInfo respInfo = new PKCS8EncryptedPrivateKeyInfo(encValue.getEncValue().getBytes());
                PrivateKeyInfo keyInfo = respInfo.decryptPrivateKeyInfo(new JceInputDecryptorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(secKeyBytes));
                assertEquals(keyInfo.getPrivateKeyAlgorithm(), encValue.getIntendedAlg());
                // Verify that we didn't get our protocol encr key back (which should be impossible since we never sent the private key over)
                assertFalse(Arrays.areEqual(protocolEncKey.getPrivate().getEncoded(), keyInfo.getEncoded()));
                // Verify that the private key returned matches the public key in the certificate we got
                PrivateKey privKey = BouncyCastleProvider.getPrivateKey(keyInfo);
                byte[] data = "foobar we want to sign this data, cats and dogs rule!".getBytes();
                byte[] signedData = KeyTools.signData(privKey, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, data);
                final boolean signatureOK = KeyTools.verifyData(cert.getPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, data, signedData);
                assertTrue(signatureOK);
                // Verify that the private/public key generated by the server is the algorithm and size that we expected
                assertEquals("RSA", privKey.getAlgorithm());
                assertEquals(1024, KeyTools.getKeyLength(cert.getPublicKey()));
            }

            // 5.

            // Try with ECC keys
            // Sending null means that the server should choose the keytype and size allowed by the certificate profile
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"ECDSA"});
            certificateProfile.setAvailableEcCurves(new String[]{"secp256r1"});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, null, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Now we should have a cert response
            pkiMessage = checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
            cert = checkCmpCertRepMessage(userDN1, this.cacert, resp, reqId);
            assertNotNull(cert);
            fingerprint2 = CertTools.getFingerprintAsString(cert);
            // We should also have a private key in the response
            {
                final PKIBody pkiBody = pkiMessage.getBody();
                final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
                final CertResponse certResponse = certRepMessage.getResponse()[0];
                final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
                EncryptedValue encValue = certifiedKeyPair.getPrivateKey();
                AsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(encValue.getKeyAlg(), protocolEncKey.getPrivate());
                byte[] secKeyBytes = (byte[])unwrapper.generateUnwrappedKey(encValue.getKeyAlg(), encValue.getEncSymmKey().getBytes()).getRepresentation();
                // recover private key
                PKCS8EncryptedPrivateKeyInfo respInfo = new PKCS8EncryptedPrivateKeyInfo(encValue.getEncValue().getBytes());
                PrivateKeyInfo keyInfo = respInfo.decryptPrivateKeyInfo(
                        new JceInputDecryptorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(secKeyBytes));
                assertEquals(keyInfo.getPrivateKeyAlgorithm(), encValue.getIntendedAlg());
                // Verify that we didn't get our protocol encr key back (which should be impossible since we never sent the private key over)
                assertFalse(Arrays.areEqual(protocolEncKey.getPrivate().getEncoded(), keyInfo.getEncoded()));
                // Verify that the private key returned matches the public key in the certificate we got
                PrivateKey privKey = BouncyCastleProvider.getPrivateKey(keyInfo);
                byte[] data = "foobar we want to sign this data, cats and dogs rule!".getBytes();
                byte[] signedData = KeyTools.signData(privKey, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, data);
                final boolean signatureOK = KeyTools.verifyData(cert.getPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, data, signedData);
                assertTrue(signatureOK);
                // Verify that the private/public key generated by the server is the algorithm and size that we expected
                assertEquals("EC", privKey.getAlgorithm());
                final String keySpec = AlgorithmTools.getKeySpecification(cert.getPublicKey());
                assertEquals("prime256v1", keySpec);
            }

            // 6.

            // Instead of sending an empty public key, send a SubjectPublicKeyInfo with empty bitstring as specified in RFC4210:
            // First we try specifying RSA key, but profile only allows ECDSA, should fail
            //
            // "Note that subjectPublicKeyInfo MAY be present and contain an AlgorithmIdentifier followed by a zero-length BIT STRING for the subjectPublicKey
            // "if it is desired to inform the CA/RA of algorithm and parameter preferences regarding the to-be-generated key pair"
            // Server should then get the algorithm from the SubjectPublicKeyInfo
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"ECDSA"});
            certificateProfile.setAvailableEcCurves(new String[]{"secp256r1"});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            // Start with RSA public key info, with empty BITString
            // Note for a normal RSA key the AlgorithmIdentifier.parameters is specified to be DERNull (not java null, but ASN.1 type null)
            // See RFC3279 for SubjectPublicKeyInfo OIDs and parameters for RSA, ECDSA etc
            SubjectPublicKeyInfo spkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new byte[0]);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, spkInfo, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "RSA key generation requested, but certificate profile specified does not allow RSA");

            // 7.

            // Same as above, but profile allows multiple RSA key sizes, should fail
            //
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"RSA"});
            certificateProfile.setAvailableBitLengths(new int[] {1024, 2048});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            // Start with RSA public key info, with empty BITString
            // Note for a normal RSA key the AlgorithmIdentifier.parameters is specified to be DERNull (not java null, but ASN.1 type null)
            // See RFC3279 for SubjectPublicKeyInfo OIDs and parameters for RSA, ECDSA etc
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, spkInfo, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "Certificate profile specified more than one key size, not possible to server generate keys");

            // 8.

            // Try the same but with an unsupported algorithm, should fail
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            // Start with RSA public key info, with empty BITString
            spkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.des_EDE3_CBC, DERNull.INSTANCE), new byte[0]);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, spkInfo, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest, "Server key generation requested, but SubjectPublicKeyInfo specifies unsupported algorithm 1.2.840.113549.3.7");

            // 9.

            // Instead of sending an empty public key, send a SubjectPublicKeyInfo with empty bitstring as specified in RFC4210:
            // "Note that subjectPublicKeyInfo MAY be present and contain an AlgorithmIdentifier followed by a zero-length BIT STRING for the subjectPublicKey
            // "if it is desired to inform the CA/RA of algorithm and parameter preferences regarding the to-be-generated key pair"
            // Server should then get the algorithm from the SubjectPublicKeyInfo
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"RSA"});
            certificateProfile.setAvailableBitLengths(new int[] {1024});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            // Start with RSA public key info, with empty BITString
            spkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new byte[0]);
//            SubjectPublicKeyInfo spkInfoEC = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
//                    X9ObjectIdentifiers.id_ecPublicKey, DERNull.INSTANCE), new byte[0]);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, spkInfo, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Now we should have a cert response
            pkiMessage = checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
            cert = checkCmpCertRepMessage(userDN1, this.cacert, resp, reqId);
            assertNotNull(cert);
            fingerprint3 = CertTools.getFingerprintAsString(cert);
            // We should also have a private key in the response
            {
                final PKIBody pkiBody = pkiMessage.getBody();
                final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
                final CertResponse certResponse = certRepMessage.getResponse()[0];
                final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
                EncryptedValue encValue = certifiedKeyPair.getPrivateKey();
                AsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(encValue.getKeyAlg(), protocolEncKey.getPrivate());
                byte[] secKeyBytes = (byte[])unwrapper.generateUnwrappedKey(encValue.getKeyAlg(), encValue.getEncSymmKey().getBytes()).getRepresentation();
                // recover private key
                PKCS8EncryptedPrivateKeyInfo respInfo = new PKCS8EncryptedPrivateKeyInfo(encValue.getEncValue().getBytes());
                PrivateKeyInfo keyInfo = respInfo.decryptPrivateKeyInfo(new JceInputDecryptorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(secKeyBytes));
                assertEquals(keyInfo.getPrivateKeyAlgorithm(), encValue.getIntendedAlg());
                // Verify that we didn't get our protocol encr key back (which should be impossible since we never sent the private key over)
                assertFalse(Arrays.areEqual(protocolEncKey.getPrivate().getEncoded(), keyInfo.getEncoded()));
                // Verify that the private key returned matches the public key in the certificate we got
                PrivateKey privKey = BouncyCastleProvider.getPrivateKey(keyInfo);
                byte[] data = "foobar we want to sign this data, cats and dogs rule!".getBytes();
                byte[] signedData = KeyTools.signData(privKey, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, data);
                final boolean signatureOK = KeyTools.verifyData(cert.getPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, data, signedData);
                assertTrue(signatureOK);
                // Verify that the private/public key generated by the server is the algorithm and size that we expected
                assertEquals("RSA", privKey.getAlgorithm());
                assertEquals(1024, KeyTools.getKeyLength(cert.getPublicKey()));
            }

            // 10.

            // Same as above with ECDSA, first specify a curve that isn't allowed in the profile
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"ECDSA"});
            certificateProfile.setAvailableEcCurves(new String[]{"secp256r1"});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            // Try with an ECDSA public key info, with empty BITString
            // See RFC3279 for SubjectPublicKeyInfo OIDs and parameters for RSA, ECDSA etc
            // We'll specify the named curve we request here
            X962Parameters params = new X962Parameters(X9ObjectIdentifiers.prime192v1);
            spkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                    X9ObjectIdentifiers.id_ecPublicKey, params), new byte[0]);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, spkInfo, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Expect a CertificateResponse (reject) message with error FailInfo.BAD_REQUEST
            checkCmpPKIErrorMessage(resp, ISSUER_DN, userDN1, PKIFailureInfo.badRequest,
                    "ECDSA key generation requested, but X962Parameters curve is none of the allowed named curves: prime192v1");

            // 11.

            // Change the profile to allow the curve we specify as params to SubjectPublicKeyInfo
            this.endEntityManagementSession.setUserStatus(ADMIN, cmptestUsername, EndEntityConstants.STATUS_NEW);
            certificateProfile.setAvailableKeyAlgorithms(new String[]{"ECDSA"});
            certificateProfile.setAvailableEcCurves(new String[]{"prime192v1", "secp256r1"});
            certProfileSession.changeCertificateProfile(ADMIN, cmptestCPName, certificateProfile);
            // Try with an ECDSA public key info, with empty BITString, but with params specifying a curve
            // See RFC3279 for SubjectPublicKeyInfo OIDs and parameters for RSA, ECDSA etc
            // We'll specify the named curve we request here
            spkInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                    X9ObjectIdentifiers.id_ecPublicKey, params), new byte[0]);
            req = genCertReq(ISSUER_DN, userDN1, userDN1, null, /*keys*/null, spkInfo, protocolEncKey, cacert, nonce, transid, false,
                    null, null, null, null, pAlg, null, false);
            assertNotNull(req);
            ir = (CertReqMessages) req.getBody().getContent();
            reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, cmpAlias);
            // Now we should have a cert response
            pkiMessage = checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
            cert = checkCmpCertRepMessage(userDN1, this.cacert, resp, reqId);
            assertNotNull(cert);
            fingerprint4 = CertTools.getFingerprintAsString(cert);
            // We should also have a private key in the response
            {
                final PKIBody pkiBody = pkiMessage.getBody();
                final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
                final CertResponse certResponse = certRepMessage.getResponse()[0];
                final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
                EncryptedValue encValue = certifiedKeyPair.getPrivateKey();
                AsymmetricKeyUnwrapper unwrapper = new JceAsymmetricKeyUnwrapper(encValue.getKeyAlg(), protocolEncKey.getPrivate());
                byte[] secKeyBytes = (byte[])unwrapper.generateUnwrappedKey(encValue.getKeyAlg(), encValue.getEncSymmKey().getBytes()).getRepresentation();
                // recover private key
                PKCS8EncryptedPrivateKeyInfo respInfo = new PKCS8EncryptedPrivateKeyInfo(encValue.getEncValue().getBytes());
                PrivateKeyInfo keyInfo = respInfo.decryptPrivateKeyInfo(new JceInputDecryptorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(secKeyBytes));
                assertEquals(keyInfo.getPrivateKeyAlgorithm(), encValue.getIntendedAlg());
                // Verify that we didn't get our protocol encr key back (which should be impossible since we never sent the private key over)
                assertFalse(Arrays.areEqual(protocolEncKey.getPrivate().getEncoded(), keyInfo.getEncoded()));
                // Verify that the private key returned matches the public key in the certificate we got
                PrivateKey privKey = BouncyCastleProvider.getPrivateKey(keyInfo);
                byte[] data = "foobar we want to sign this data, cats and dogs rule!".getBytes();
                byte[] signedData = KeyTools.signData(privKey, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, data);
                final boolean signatureOK = KeyTools.verifyData(cert.getPublicKey(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, data, signedData);
                assertTrue(signatureOK);
                // Verify that the private/public key generated by the server is the algorithm and size that we expected
                assertEquals("EC", privKey.getAlgorithm());
                final String keySpec = AlgorithmTools.getKeySpecification(cert.getPublicKey());
                assertEquals("prime192v1", keySpec);
            }

        } finally {
            log.debug("Deleting certificate: "+fingerprint1);
            this.internalCertStoreSession.removeCertificate(fingerprint1);
            log.debug("Deleting certificate: "+fingerprint2);
            this.internalCertStoreSession.removeCertificate(fingerprint2);
            log.debug("Deleting certificate: "+fingerprint3);
            this.internalCertStoreSession.removeCertificate(fingerprint3);
            log.debug("Deleting certificate: "+fingerprint4);
            this.internalCertStoreSession.removeCertificate(fingerprint4);
            log.debug("Deleting user: "+cmptestUsername);
            try {
            this.endEntityManagementSession.deleteUser(ADMIN, cmptestUsername);
            } catch (NoSuchEndEntityException e) {
                // NOPMD: ignore
            }
            // Re-set CMP alias configuration
            this.cmpConfiguration.setAllowServerGeneratedKeys(cmpAlias, false);
            this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
            // Restore certificate profile to what it was before the test
            this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, backup);
        }
        log.trace("<test12ServerGeneratedKeys");
    }


    /*
     *     header
     *         pvno: cmp2000 (2)
     *         sender: 4
     *             directoryName: rdnSequence (0)
     *                 rdnSequence: 0 items
     *         recipient: 4
     *             directoryName: rdnSequence (0)
     *                 rdnSequence: 4 items (id-at-commonName=Test CA 1,id-at-organizationalUnitName=Development,id-at-organizationName=A.E.T. Europe B.V.,id-at-countryName=NL)
     *                     RDNSequence item: 1 item (id-at-countryName=NL)
     *                         RelativeDistinguishedName item (id-at-countryName=NL)
     *                             Id: 2.5.4.6 (id-at-countryName)
     *                             CountryName: NL
     *                     RDNSequence item: 1 item (id-at-organizationName=A.E.T. Europe B.V.)
     *                         RelativeDistinguishedName item (id-at-organizationName=A.E.T. Europe B.V.)
     *                             Id: 2.5.4.10 (id-at-organizationName)
     *                             DirectoryString: printableString (1)
     *                                 printableString: A.E.T. Europe B.V.
     *                     RDNSequence item: 1 item (id-at-organizationalUnitName=Development)
     *                         RelativeDistinguishedName item (id-at-organizationalUnitName=Development)
     *                             Id: 2.5.4.11 (id-at-organizationalUnitName)
     *                             DirectoryString: printableString (1)
     *                                 printableString: Development
     *                     RDNSequence item: 1 item (id-at-commonName=Test CA 1)
     *                         RelativeDistinguishedName item (id-at-commonName=Test CA 1)
     *                             Id: 2.5.4.3 (id-at-commonName)
     *                             DirectoryString: printableString (1)
     *                                 printableString: Test CA 1
     *         protectionAlg (PasswordBasedMac)
     *             Algorithm Id: 1.2.840.113533.7.66.13 (PasswordBasedMac)
     *             PBMParameter
     *                 salt: 02bf1fb0e8fb9e4def6e0a76fc66ecd7
     *                 owf (SHA-1)
     *                     Algorithm Id: 1.3.14.3.2.26 (SHA-1)
     *                 iterationCount: 1000
     *                 mac (HMAC SHA-1)
     *                     Algorithm Id: 1.3.6.1.5.5.8.1.2 (HMAC SHA-1)
     *         senderKID: 73736c636c69656e74
     *         transactionID: a45a41b289df8675bc89ad68b46721ad
     *         senderNonce: 32cddde790a033709a8616b0f0d23918
     *     body: ir (0)
     *         ir: 1 item
     *             CertReqMsg
     *                 certReq
     *                     certReqId: 0
     *                     certTemplate
     *                         validity
     *                             notBefore: generalTime (1)
     *                                 generalTime: 2006-09-19 16:11:26 (UTC)
     *                             notAfter: generalTime (1)
     *                                 generalTime: 2009-06-15 16:11:26 (UTC)
     *                         subject: 0
     *                             rdnSequence: 1 item (id-at-commonName=Some Common Name)
     *                                 RDNSequence item: 1 item (id-at-commonName=Some Common Name)
     *                                     RelativeDistinguishedName item (id-at-commonName=Some Common Name)
     *                                         Id: 2.5.4.3 (id-at-commonName)
     *                                         DirectoryString: uTF8String (4)
     *                                             uTF8String: Some Common Name
     *                         publicKey
     *                             algorithm (rsaEncryption)
     *                                 Algorithm Id: 1.2.840.113549.1.1.1 (rsaEncryption)
     *                             Padding: 0
     *                             subjectPublicKey: 30818a02818100b8181318f817ad2dc020f37a8973ba2cd7...
     *                         extensions: 1 item
     *                             Extension
     *                                 Id: 2.5.29.17 (id-ce-subjectAltName)
     *                                 GeneralNames: 1 item
     *                                     GeneralName: otherName (0)
     *                                         otherName
     *                                             type-id: 1.3.6.1.4.1.311.20.2.3 (id-ms-user-principal-name)
     *                                             UTF8String: upn@aeteurope.nl
     *                 popo: raVerified (0)
     *                     raVerified
     *     Padding: 0
     *     protection: 32fef4a83547af71d5315e4090c777efc648e1e8
     */
    static byte[] bluexir = Base64.decode(("MIICIjCB1AIBAqQCMACkVjBUMQswCQYDVQQGEwJOTDEbMBkGA1UEChMSQS5FLlQu"
            + "IEV1cm9wZSBCLlYuMRQwEgYDVQQLEwtEZXZlbG9wbWVudDESMBAGA1UEAxMJVGVz" + "dCBDQSAxoT4wPAYJKoZIhvZ9B0INMC8EEAK/H7Do+55N724Kdvxm7NcwCQYFKw4D"
            + "AhoFAAICA+gwDAYIKwYBBQUIAQIFAKILBAlzc2xjbGllbnSkEgQQpFpBsonfhnW8" + "ia1otGchraUSBBAyzd3nkKAzcJqGFrDw0jkYoIIBLjCCASowggEmMIIBIAIBADCC"
            + "ARmkJqARGA8yMDA2MDkxOTE2MTEyNlqhERgPMjAwOTA2MTUxNjExMjZapR0wGzEZ" + "MBcGA1UEAwwQU29tZSBDb21tb24gTmFtZaaBoDANBgkqhkiG9w0BAQEFAAOBjgAw"
            + "gYoCgYEAuBgTGPgXrS3AIPN6iXO6LNf5GzAcb/WZhvebXMdxdrMo9+5hw/Le5St/" + "Sz4J93rxU95b2LMuHTg8U6njxC2lZarNExZTdEwnI37X6ep7lq1purq80zD9bFXj"
            + "ougRD5MHfhDUAQC+btOgEXkanoAo8St3cbtHoYUacAXN2Zs/RVcCBAABAAGpLTAr" + "BgNVHREEJDAioCAGCisGAQQBgjcUAgOgEgwQdXBuQGFldGV1cm9wZS5ubIAAoBcD"
            + "FQAy/vSoNUevcdUxXkCQx3fvxkjh6A==").getBytes());

    /*
     *	header:
     *		pvno: cmp2000 (cmp.pvno = 2)
     *		sender: 4	(cmp.sender = 4)
     *			directoryName: rdnSequence (0)		(x509ce.directoryName = 0)
     *				rdnSequence: 4 items (id-at-commonName=21030533610000000012 eNodeB,id-at-organizationalUnitName=Wireless Network Product Line,id-at-organizationName=Huawei,id-at-countryName=CN)
     *					RDNSequence item: 1 item (id-at-countryName=CN)					(x509if.RDNSequence_item = 1)
     *						RelativeDistinguishedName item (id-at-countryName=CN)		(x509if.RelativeDistinguishedName_item = 1)
     *							Id: 2.5.4.6 (id-at-countryName)							(x509if.id = 2.5.4.6)
     *							CountryName: CN											(x509sat.CountryName = CN)
     *					RDNSequence item: 1 item (id-at-organizationName=Huawei)
     *					RDNSequence item: 1 item (id-at-organizationalUnitName=Wireless Network Product Line)
     *					RDNSequence item: 1 item (id-at-commonName=21030533610000000012 eNodeB)
     *		recipient: 4
     *			directoryName: rdnSequence (0)
     *				rdnSequence: 6 items (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *					RDNSequence item: 1 item (id-at-countryName=cn)
     *					RDNSequence item: 1 item (id-at-stateOrProvinceName=sh)
     *					RDNSequence item: 1 item (id-at-localityName=qc)
     *					RDNSequence item: 1 item (id-at-organizationName=wl)
     *					RDNSequence item: 1 item (id-at-organizationalUnitName=lte)
     *					RDNSequence item: 1 item (id-at-commonName=enbca)
     *		protectionAlg (shaWithRSAEncryption)
     *			Algorithm Id: 1.2.840.113549.1.1.5 (shaWithRSAEncryption)
     *		transactionID: 46E72888
     *		senderNonce: 219F0452
     *		recipNonce: 00000000
     *	body: ir (0)
     *		ir: 1 item
     *			CertReqMsg
     *				certReq
     *					certReqId: 355
     *					certTemplate
     *						version: v3 (2)
     *						validity
     *							notBefore: utcTime (0)
     *								utcTime: 10-06-01 09:44:01 (UTC)
     *							notAfter: utcTime (0)
     *								utcTime: 11-06-01 09:44:01 (UTC)
     *						subject: 0
     *							rdnSequence: 1 item (id-at-commonName=21030533610000000012 eNodeB)
     *								RDNSequence item: 1 item (id-at-commonName=21030533610000000012 eNodeB)
     *									RelativeDistinguishedName item (id-at-commonName=21030533610000000012 eNodeB)
     *										Id: 2.5.4.3 (id-at-commonName)
     *										DirectoryString: uTF8String (4)
     *											uTF8String: 21030533610000000012 eNodeB
     *						publicKey
     *							algorithm (rsaEncryption)
     *								Algorithm Id: 1.2.840.113549.1.1.1 (rsaEncryption)
     *							Padding: 0
     *							subjectPublicKey: 3082010A02820101009C2BCD07CBB0CF2B8B75062668D64F...
     *						extensions: 2 items
     *							Extension
     *								Id: 2.5.29.15 (id-ce-keyUsage)
     *								critical: True
     *								Padding: 3
     *								KeyUsage: B8 (digitalSignature, keyEncipherment, dataEncipherment, keyAgreement)
     *									1... .... = digitalSignature: True
     *									.0.. .... = contentCommitment: False
     *									..1. .... = keyEncipherment: True
     *									...1 .... = dataEncipherment: True
     *									.... 1... = keyAgreement: True
     *									.... .0.. = keyCertSign: False
     *									.... ..0. = cRLSign: False
     *									.... ...0 = encipherOnly: False
     *									0... .... = decipherOnly: False
     *							Extension
     *								Id: 2.5.29.17 (id-ce-subjectAltName)
     *								critical: True
     *								GeneralNames: 1 item
     *									GeneralName: dNSName (2)
     *										dNSName: 21030533610000000012.huawei.com
     *				popo: signature (1)
     *					signature
     *						algorithmIdentifier (shaWithRSAEncryption)
     *							Algorithm Id: 1.2.840.113549.1.1.5 (shaWithRSAEncryption)
     *						Padding: 0
     *						signature: 403F2C7C4A1C777D3F09132FBBAC3FCA058CD4EE1F461F24...
     *		Padding: 0
     *		protection: 73FEA50585570F1B3CD16E3A744546251D0C206FC67B2554...
     *		extraCerts: 3 items
     *			CMPCertificate: x509v3PKCert (0)
     *				signedCertificate
     *					version: v3 (2)
     *					serialNumber : 0x00bad55b3947cb876dc391f7798438d2a5
     *					signature (shaWithRSAEncryption) :
     *						Algorithm Id: 1.2.840.113549.1.1.5 (shaWithRSAEncryption)
     *					issuer: rdnSequence (0)
     *						rdnSequence: 4 items (id-at-commonName=Huawei Wireless Network Product CA,id-at-organizationalUnitName=Wireless Network Product Line,id-at-organizationName=Huawei,id-at-countryName=CN)
     *					validity
     *						notBefore: utcTime (0)
     *							utcTime: 10-11-12 07:39:38 (UTC)
     *						notAfter: utcTime (0)
     *							utcTime: 34-10-17 09:00:35 (UTC)
     *					subject: rdnSequence (0)
     *						rdnSequence: 4 items (id-at-commonName=21030533610000000012 eNodeB,id-at-organizationalUnitName=Wireless Network Product Line,id-at-organizationName=Huawei,id-at-countryName=CN)
     *					subjectPublicKeyInfo
     *						algorithm (rsaEncryption)
     *							Algorithm Id: 1.2.840.113549.1.1.1 (rsaEncryption)
     *						Padding: 0
     *						subjectPublicKey: 30818902818100BE8880B56877C44F300EAB825C198B8FF3...
     *					extensions: 2 items
     *						Extension (id-ce-keyUsage)
     *							Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *							critical: True
     *							Padding: 0
     *							KeyUsage: B8 (digitalSignature, keyEncipherment, dataEncipherment, keyAgreement)
     *						Extension Id: 2.5.29.17 (id-ce-subjectAltName)
     *							GeneralNames: 1 item
     *								GeneralName: dNSName (2)
     *									dNSName: 21030533610000000012.Huawei.com
     *			CMPCertificate: x509v3PKCert (0)
     *				x509v3PKCert (id-at-commonName=Huawei Wireless Network Product CA,id-at-organizationalUnitName=Wireless Network Product Line,id-at-organizationName=Huawei,id-at-countryName=CN)
     *					signedCertificate
     *						version: v3 (2)
     *						serialNumber : 0x00b2c83453e95b7df146f96729bdd7172c
     *						signature (shaWithRSAEncryption)
     *						issuer: rdnSequence (0)
     *							rdnSequence: 3 items (id-at-commonName=Huawei Equipment CA,id-at-organizationName=Huawei,id-at-countryName=CN)
     *						validity
     *							notBefore: utcTime (0)
     *								utcTime: 09-10-19 09:30:34 (UTC)
     *							notAfter: utcTime (0)
     *								utcTime: 34-10-18 09:00:35 (UTC)
     *						subject: rdnSequence (0)
     *							rdnSequence: 4 items (id-at-commonName=Huawei Wireless Network Product CA,id-at-organizationalUnitName=Wireless Network Product Line,id-at-organizationName=Huawei,id-at-countryName=CN)
     *						subjectPublicKeyInfo
     *							algorithm (rsaEncryption)
     *							Padding: 0
     *							subjectPublicKey: 3082010A0282010100C137F5D3877167EFA1CEDD31D27FAE...
     *						extensions: 4 items
     *							Extension (id-ce-basicConstraints)
     *								Extension Id: 2.5.29.19 (id-ce-basicConstraints)
     *								BasicConstraintsSyntax
     *									cA: True
     *							Extension (id-ce-keyUsage)
     *								Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *									critical: True
     *									Padding: 1
     *									KeyUsage: 06 (keyCertSign, cRLSign)
     *							Extension (id-ce-subjectKeyIdentifier)
     *								Extension Id: 2.5.29.14 (id-ce-subjectKeyIdentifier)
     *									SubjectKeyIdentifier: 5E7017DC6FA40748033787FE3DB4C720D636B8D0
     *							Extension (id-ce-authorityKeyIdentifier)
     *								Extension Id: 2.5.29.35 (id-ce-authorityKeyIdentifier)
     *								AuthorityKeyIdentifier
     *									keyIdentifier: 2AF810592780351FA77CBA3B9F2AE44AAA9B92EA
     *					algorithmIdentifier (shaWithRSAEncryption)
     *					Padding: 0
     *					encrypted: 931FC67E865E1969E22B29A5C578A0EBB79E5A0AE29EC888...
     *			CMPCertificate: x509v3PKCert (0)
     *				x509v3PKCert (id-at-commonName=Huawei Equipment CA,id-at-organizationName=Huawei,id-at-countryName=CN)
     *					signedCertificate
     *						version: v3 (2)
     *						serialNumber : 0x00f2ff51cc6584f1980824d984b3cdbd5b
     *						signature (shaWithRSAEncryption)
     *						issuer: rdnSequence (0)
     *							rdnSequence: 3 items (id-at-commonName=Huawei Equipment CA,id-at-organizationName=Huawei,id-at-countryName=CN)
     *						validity
     *							notBefore: utcTime (0)
     *								utcTime: 09-10-19 09:00:28 (UTC)
     *							notAfter: utcTime (0)
     *								utcTime: 34-10-19 09:00:00 (UTC)
     *						subject: rdnSequence (0)
     *							rdnSequence: 3 items (id-at-commonName=Huawei Equipment CA,id-at-organizationName=Huawei,id-at-countryName=CN)
     *						subjectPublicKeyInfo
     *							algorithm (rsaEncryption)
     *							Padding: 0
     *							subjectPublicKey: 3082020A0282020100A28984270BF329F686E60275E6BBF3...
     *						extensions: 4 items
     *							Extension (id-ce-keyUsage)
     *								Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *								critical: True
     *								Padding: 1
     *								KeyUsage: 86 (digitalSignature, keyCertSign, cRLSign)
     *							Extension (id-ce-basicConstraints)
     *								Extension Id: 2.5.29.19 (id-ce-basicConstraints)
     *								BasicConstraintsSyntax
     *									cA: True
     *							Extension (id-ce-subjectKeyIdentifier)
     *								Extension Id: 2.5.29.14 (id-ce-subjectKeyIdentifier)
     *								SubjectKeyIdentifier: 2AF810592780351FA77CBA3B9F2AE44AAA9B92EA
     *							Extension (id-ce-authorityKeyIdentifier)
     *								Extension Id: 2.5.29.35 (id-ce-authorityKeyIdentifier)
     *								AuthorityKeyIdentifier
     *									keyIdentifier: 2AF810592780351FA77CBA3B9F2AE44AAA9B92EA
     *					algorithmIdentifier (shaWithRSAEncryption)
     *					Padding: 0
     *					encrypted: 000B6246A8239D21F35786BBE6E6E96E8E7D7C17C7679C87...
     */
    static byte[] telefonica = Base64.decode(("MIIRmTCB8gIBAqRuMGwxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKEwZIdWF3ZWkxJjAkBgNVBAsTHVdp"
            + "cmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBMaW5lMSQwIgYDVQQDExsyMTAzMDUzMzYxMDAwMDAwMDAx"
            + "MiBlTm9kZUKkVDBSMQswCQYDVQQGEwJjbjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnFjMQswCQYD"
            + "VQQKEwJ3bDEMMAoGA1UECxMDbHRlMQ4wDAYDVQQDEwVlbmJjYaEPMA0GCSqGSIb3DQEBBQUApAYE"
            + "BEbnKIilBgQEIZ8EUqYGBAQAAAAAoIIC5DCCAuAwggLcMIIBwAICAWMwggG4gAECpCKgDxcNMTAw"
            + "NjAxMDk0NDAxWqEPFw0xMTA2MDEwOTQ0MDFapSgwJjEkMCIGA1UEAwwbMjEwMzA1MzM2MTAwMDAw"
            + "MDAwMTIgZU5vZGVCpoIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCvNB8uwzyuLdQYm"
            + "aNZPP3jAZ0DL+9iPzJPaHUdQi2qG5tkoYy6UcH/WlJM90QIgr+XHK6rLCLWnk07APf/F9UDxhCpn"
            + "9BWM51c4MwSDnoSvFIdqOwsTSAirvkUAscF3OeW34RrXZRCmsl5jSND4MuRyUsDQcty1U/bj1U4g"
            + "lQdC+RwjwBYFK2K580ugEuz/x4nUtfqyjv7FFPY1ct2e5dQ/9Pbg/tq06oxMLuWO53IVRZ0WwACQ"
            + "bUIcr0bdlfwm7WqkHJEU51SdEDisfS/SyiK5NYfjEa2D/ZiGLREUgUx5uDc4NNjdHOycQ/0L1i9z"
            + "aOoyKbadUZFITdcglHaS4wIDAQABqT8wDgYDVR0PAQH/BAQDAgO4MC0GA1UdEQEB/wQjMCGCHzIx"
            + "MDMwNTMzNjEwMDAwMDAwMDEyLmh1YXdlaS5jb22hggEUMA0GCSqGSIb3DQEBBQUAA4IBAQBAPyx8"
            + "Shx3fT8JEy+7rD/KBYzU7h9GHyQ9fvdvUmVuqCvIVncbXwEDk+vInvkiCoBRgJxI2tmiwguJT4mQ"
            + "yIq4TBdunabLqEbL7Me36cYQH3mY68v4YzAnHYcM7eAcdxXDivxFuKwSxQ2yoVrncaPb8/tHmQdx"
            + "XOzi0MmkksFe3IR25qh6G9Jz+TRmGWtTuzEuF87oyUyUb8boCLeMJ5FUKidavI/fmqSKa+iX0vVW"
            + "T069pXCdtWdOZA4dc6ya7AEIifNUTLon03a/rtWXat+J4qnH1u2u2UgmItoiXjcur2tEGnPiGpxl"
            + "GiP+qbWQBzNM0GRIO7ldjbMztsLYSGd2oIGEA4GBAHP+pQWFVw8bPNFuOnRFRiUdDCBvxnslVOHD"
            + "2e5864lisPtoeSUXsLM/6Dqfa8Q8WDiKRht4t7X5QEr8aYv/Q7g4g9Q7MBl3UgV2xt44XS2c1ZXA"
            + "cbVvE6KzTFKlq5LtVsVsTFfnO1OiGrdwXzxeTNu94QUcLg7MkvhT4AON/QzwoYINMTCCDS0wggMk"
            + "MIICDKADAgECAhEAutVbOUfLh23Dkfd5hDjSpTANBgkqhkiG9w0BAQUFADBzMQswCQYDVQQGEwJD"
            + "TjEPMA0GA1UEChMGSHVhd2VpMSYwJAYDVQQLEx1XaXJlbGVzcyBOZXR3b3JrIFByb2R1Y3QgTGlu"
            + "ZTErMCkGA1UEAxMiSHVhd2VpIFdpcmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBDQTAeFw0xMDExMTIw"
            + "NzM5MzhaFw0zNDEwMTcwOTAwMzVaMGwxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKEwZIdWF3ZWkxJjAk"
            + "BgNVBAsTHVdpcmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBMaW5lMSQwIgYDVQQDExsyMTAzMDUzMzYx"
            + "MDAwMDAwMDAxMiBlTm9kZUIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL6IgLVod8RPMA6r"
            + "glwZi4/zrgSSh1+04JLuB7Xbm3dGFmK8BoqUMqMBOtaE5x+apY6x8ZfJYLpLZQ1GfnsEEwJtUIh3"
            + "9zsGXKW8m5nCsXK6z0j7/t1a9ZdD1/4cAVN5bap6HLxC2bLKIsiiXsMr/6bvq5hCmoHLzHEG6TAP"
            + "I6qHAgMBAAGjPjA8MA4GA1UdDwEB/wQEAwIAuDAqBgNVHREEIzAhgh8yMTAzMDUzMzYxMDAwMDAw"
            + "MDAxMi5IdWF3ZWkuY29tMA0GCSqGSIb3DQEBBQUAA4IBAQB0hZ1CqMQLWzyYmxB/2X5s8BWX32zM"
            + "dk5M0X9xe7k4TuNyCCcv7GjYEVdda95VS0GPkYs8tUxaVPb2SQv7W5uNXy7sz6hr56xPJlbpkt01"
            + "yJYknlXFK4L+nEG7tszuSdu+1Q2gcO9OUOrkrm4I9Nx7KNhJuYtXjAtrs8DSmGITKtY1r3d63CAo"
            + "JuOGeBirRmMeiXCYlEZjLYrd14b0cp51FuKcj883DESTjHysc7Z3fHujqY3ZRhwaUqItYyGYSufN"
            + "wPmbmzZ5vBH813qekKeTh+4nK3pUTwSx4exXhIOqpWHyx9WGsLrDJ38EC8Mw1DJh4zMyfKGuGsKH"
            + "CukbJWkTMIIEmjCCAoKgAwIBAgIRALLINFPpW33xRvlnKb3XFywwDQYJKoZIhvcNAQEFBQAwPDEL"
            + "MAkGA1UEBhMCQ04xDzANBgNVBAoTBkh1YXdlaTEcMBoGA1UEAxMTSHVhd2VpIEVxdWlwbWVudCBD"
            + "QTAeFw0wOTEwMTkwOTMwMzRaFw0zNDEwMTgwOTAwMzVaMHMxCzAJBgNVBAYTAkNOMQ8wDQYDVQQK"
            + "EwZIdWF3ZWkxJjAkBgNVBAsTHVdpcmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBMaW5lMSswKQYDVQQD"
            + "EyJIdWF3ZWkgV2lyZWxlc3MgTmV0d29yayBQcm9kdWN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC"
            + "AQ8AMIIBCgKCAQEAwTf104dxZ++hzt0x0n+uRZahqaQYMO9qr7trvKo8XE+1mrxGbfbR3Yc8ArOJ"
            + "FQvfxq+ylI9L7qyunHEHiAfAFpWprq7ovP4lhWuzxh6At4DYKBPq0IqGZ9qVfM5Wq96uK6Vrltjj"
            + "QwS0nuAZC3b1MRYoumHbtRemjorLssD8Vh8TgCJd87wOXf4mSmPhdLqGbbeUksbQROHwtnbZuhL2"
            + "HGc+CqE6wBVE0oWD2JztJENj0myVQqq7fmBvs4zCb3Wh7M5AYUq8SeTmizboRML+wIF5kNUSV/wS"
            + "GG7GDx2sJDmB+AXg/jIMawL3ml7GBaeFZiB6QIDBsyxhsVx+AHl35wIDAQABo2AwXjAMBgNVHRME"
            + "BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUXnAX3G+kB0gDN4f+PbTHINY2uNAwHwYD"
            + "VR0jBBgwFoAUKvgQWSeANR+nfLo7nyrkSqqbkuowDQYJKoZIhvcNAQEFBQADggIBAJMfxn6GXhlp"
            + "4isppcV4oOu3nloK4p7IiMrlS53363z1SQpcvCo92gzGM3qePajCTTvnRDaggOi+xcpbfJbMG62z"
            + "+e9qqKiJ53bMk+VSs3rMTRkLIhoRHmu5rIx+5r6apS4X8+g5DykaODye+sMmT0jS9OWuo8q3Ne9u"
            + "XELSwkXjcJSy3j4n+IKC+GfY8gzM130OsHcg2rzesRxNhjc2BztYdq4tge9X0Uh5dXgjTXJnu2/Q"
            + "hNvAqjJZVy7rbAHzl7DbRjQk9bFL2Snzawq/0IapfnywRD64bGoo/GRvW9Igs7eplFAhwiIRvw9u"
            + "qgEGqsk9GiduIqgTtOOT/puH/5My2DEb+faN7uEqqQT6YYH/draE5R8zYWnCHqE2yXNOyqolwP9L"
            + "OZJQunA8YBv/2rqiimvEZGR5q9F6lXpxrGAJn9tMZFNn7GmJ33Q2BrgCBkOUj+HNcXUzVzKTo/GU"
            + "O6LimPiI367viVY5IJQlQd/WHJYjK0h7OYBLCvcTXSvUt9jNoUsah9S8SqM0vyW5QvnN9KTWuUXc"
            + "XHkE3TRO0eem1viZVhcD/5V7b05Ib9vWfHONWs66JjUa83vfvajqciFdzXftDedfe0AejkKb30/J"
            + "aBKRhSo9P8l0Yiwh8t/5Wxdoar2CiEneTH7HmkbmTcTKwDqOoODA18AGnUtTmymqMIIFYzCCA0ug"
            + "AwIBAgIRAPL/UcxlhPGYCCTZhLPNvVswDQYJKoZIhvcNAQEFBQAwPDELMAkGA1UEBhMCQ04xDzAN"
            + "BgNVBAoTBkh1YXdlaTEcMBoGA1UEAxMTSHVhd2VpIEVxdWlwbWVudCBDQTAeFw0wOTEwMTkwOTAw"
            + "MjhaFw0zNDEwMTkwOTAwMDBaMDwxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKEwZIdWF3ZWkxHDAaBgNV"
            + "BAMTE0h1YXdlaSBFcXVpcG1lbnQgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCi"
            + "iYQnC/Mp9obmAnXmu/Nj6rccSkEQJXlZipOv8tIjvr0B8ObpFUnU+qLojZUYlNmXH8RgRgFB1sBS"
            + "yOuGiiP0uNtJ0lPLbylsc+2fr2Rlt/qbYs1oQGz+oNl+UdAOtm/lPzggUOVVst15Ovf0Yf6LQ3CQ"
            + "alN2VJWgKpFUudDKWQ2fzbFT5YSfvhFxvtvWfgdntKAJt3sFvkKr9Qw+0EYNpQiw5EALeLWCZSYU"
            + "7A939puqYR6aNA447S1K8SgWoav82P4UY/ykLXjcgTeCnvRRtUga1gdIwm5d/vRlB5il5wspGLLe"
            + "s4SomzUYrvnvHio555NZPpvmpIXNolwvYW5opAyYzE05pVSOmHf/RY/dHto8XWexOJq/UAFBMyiH"
            + "4NT4cZpWjYWR7W9GxRXApmQrrLXte1CF/IzXWBMA2tSL0WnRJz5HRcKzsOC6FksiqsYstFjcCE7J"
            + "7Nicr3Bwq5FrZiqGSdLmLRn97XqVlWdN31HX16fzRhZMiOkvQe+uYT+BXbhU1fZIh6RRAH3V1APo"
            + "bVlCXh5PDq8Ca4dClHNHYp5RP0Pb5zBowTqBzSv7ssHrNceQsWDeNjX9t59NwviaIlXIlPiWEEJc"
            + "22XtMm4sc/+8mgOFMNXr4FWu8vdG2fgRpeWJO0E035D6TClu4So2GlN/fIccp5wVYAWF1WhxSQID"
            + "AQABo2AwXjAOBgNVHQ8BAf8EBAMCAYYwDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUKvgQWSeANR+n"
            + "fLo7nyrkSqqbkuowHwYDVR0jBBgwFoAUKvgQWSeANR+nfLo7nyrkSqqbkuowDQYJKoZIhvcNAQEF"
            + "BQADggIBAAALYkaoI50h81eGu+bm6W6OfXwXx2ech9r/JkYiv8NDE1gXFaqbqVTgmTMVAWIIyiYF"
            + "zFedILyhnva4zIqtBUKVTM1WU8Bx0TqLRp2/KRSX9q2AIHA7cKTYUn6XGzV4amqa3nXJ/v0q9Sty"
            + "rYqY9piARqoOTseAu4WhMQvyPgTkQ7lFJ97HOvDBM/BNFoPo9DrdLJlBaNIUngjB1c/ZkvXfDUhP"
            + "B7fegH8dY2hkGD/We0jnkEQA6ch6h/c24wJzVA9VZK6UX2KikYvFS9yipdS5ry6chRSt29UtbTEO"
            + "q4airI3U/IuxkSAEiVuasLLkGTQTJgTfroFIE0/MiTsyfmxHiMZM0vN2gaPjW+zfkxpqcQcGeNRR"
            + "jMC2Kh/bMN1is5rzoh3jWADG8tWBQjlSghxNFwAgPMV6ui3SIgNPd07LVwzMQIpMzSn670CtpGKu"
            + "KB3wchnW2JjEGd9Zb49aP1a+83pBvgUVHaZ5KTlV4lrSe/s8e3SFMiV/6p+KAnV5/cnSnuNJfl0u"
            + "Tjavw7DEqcXV6UN0Eg571WLRZvnsmCWAHncBMQ7prVDTdnc7OVsZw0TnTzcBYZtYl2mdxsR3tb3k"
            + "YngXwIxzWROeEFWpNvWnuSzEH+Vv939rdvgLzHrcYgZuvknyWx5Vp9c+ezA58JWYo/nNBFzb0/U1" + "OZck9LLi").getBytes());

    /*
     *header
     *	pvno: cmp2000 (2)
     *	sender: 4
     *		rdnSequence: 6 items (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *	recipient: 4
     *		rdnSequence: 4 items (id-at-commonName=21030533610000000012 eNodeB,id-at-organizationalUnitName=Wireless Network Product Line,id-at-organizationName=Huawei,id-at-countryName=CN)
     *	messageTime: 2011-02-22 17:56:01 (UTC)
     *	protectionAlg (shaWithRSAEncryption)
     *	transactionID: 46E72888
     *	senderNonce: 13AC3DBA7D81873B06218096A2AAE044
     *	recipNonce: 219F0452
     *body: ip (1)
     *	ip
     *		caPubs: 1 item
     *			CMPCertificate: x509v3PKCert (0)
     *				x509v3PKCert (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *					signedCertificate
     *						version: v3 (2)
     *						serialNumber : 0x00b252ce935b1feb3a
     *						signature (shaWithRSAEncryption)
     *						issuer: rdnSequence: 6 items (id-at-commonName=enbroot,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *						validity
     *							notBefore: utcTime (0)	utcTime: 10-06-03 08:33:28 (UTC)
     *							notAfter: utcTime (0)	utcTime: 11-06-03 08:33:28 (UTC)
     *						subject: rdnSequence: 6 items (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *						subjectPublicKeyInfo
     *							algorithm (rsaEncryption)
     *							Padding: 0
     *							subjectPublicKey: 30818902818100CC8C0DF283FBFD3717785A4399765994A9...
     *						extensions: 3 items
     *							Extension (id-ce-subjectKeyIdentifier)
     *								Extension Id: 2.5.29.14 (id-ce-subjectKeyIdentifier)
     *								SubjectKeyIdentifier: 4C60DB752400513F2C5F659498FB55155E230045
     *							Extension (id-ce-basicConstraints)
     *								Extension Id: 2.5.29.19 (id-ce-basicConstraints)
     *								BasicConstraintsSyntax
     *									cA: True
     *							Extension (id-ce-keyUsage)
     *								Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *								Padding: 1
     *								KeyUsage: F6 (digitalSignature, contentCommitment, keyEncipherment, dataEncipherment, keyCertSign, cRLSign)
     *					algorithmIdentifier (shaWithRSAEncryption)
     *					Padding: 0
     *					encrypted: 2A69C2FD0A809383EACB7CA16E48C8ABB3E4038A4FA288B9...
     *		response: 1 item
     *			CertResponse
     *				certReqId: 355
     *				status
     *					status: accepted (0)
     *				certifiedKeyPair
     *					certOrEncCert: certificate (0)
     *						certificate: x509v3PKCert (0)
     *							x509v3PKCert (id-at-commonName=21030533610000000012 eNodeB)
     *								signedCertificate
     *									version: v3 (2)
     *									serialNumber: -141639098
     *									signature (shaWithRSAEncryption)
     *									issuer: rdnSequence: 6 items (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *									validity
     *										notBefore: utcTime (0)	utcTime: 11-02-22 17:56:01 (UTC)
     *										notAfter: utcTime (0)	utcTime: 11-06-03 08:33:28 (UTC)
     *									subject: rdnSequence (0)	rdnSequence: 1 item (id-at-commonName=21030533610000000012 eNodeB)
     *									subjectPublicKeyInfo
     *										algorithm (rsaEncryption)
     *										Padding: 0
     *										subjectPublicKey: 3082010A02820101009C2BCD07CBB0CF2B8B75062668D64F...
     *									extensions: 2 items
     *										Extension (id-ce-keyUsage)
     *											Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *											critical: True
     *											Padding: 3
     *											KeyUsage: B8 (digitalSignature, keyEncipherment, dataEncipherment, keyAgreement)
     *										Extension (id-ce-subjectAltName)
     *											Extension Id: 2.5.29.17 (id-ce-subjectAltName)
     *											critical: True
     *											GeneralNames: 1 item		dNSName: 21030533610000000012.huawei.com
     *								algorithmIdentifier (shaWithRSAEncryption)
     *								Padding: 0
     *								encrypted: 64B737A8AF0A27CB19D66D3357D35B62ECFEA26C4A589CB7...
     *	Padding: 0
     *	protection: 7C95130034E67A9E87B05B2469B4FE5523C0213A73A32C1B...
     *	extraCerts: 2 items
     *		CMPCertificate: x509v3PKCert (0)
     *			x509v3PKCert (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *				signedCertificate
     *					version: v3 (2)
     *					serialNumber : 0x00b252ce935b1feb3a
     *					signature (shaWithRSAEncryption)
     *					issuer: rdnSequence: 6 items (id-at-commonName=enbroot,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *					validity
     *						notBefore: utcTime (0)		utcTime: 10-06-03 08:33:28 (UTC)
     *						notAfter: utcTime (0)		utcTime: 11-06-03 08:33:28 (UTC)
     *					subject: rdnSequence: 6 items (id-at-commonName=enbca,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *					subjectPublicKeyInfo
     *						algorithm (rsaEncryption)
     *						Padding: 0
     *						subjectPublicKey: 30818902818100CC8C0DF283FBFD3717785A4399765994A9...
     *						extensions: 3 items
     *							Extension (id-ce-subjectKeyIdentifier)
     *								Extension Id: 2.5.29.14 (id-ce-subjectKeyIdentifier)
     *								SubjectKeyIdentifier: 4C60DB752400513F2C5F659498FB55155E230045
     *							Extension (id-ce-basicConstraints)
     *								Extension Id: 2.5.29.19 (id-ce-basicConstraints)
     *								BasicConstraintsSyntax
     *									cA: True
     *							Extension (id-ce-keyUsage)
     *								Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *								Padding: 1
     *								KeyUsage: F6 (digitalSignature, contentCommitment, keyEncipherment, dataEncipherment, keyCertSign, cRLSign)
     *				algorithmIdentifier (shaWithRSAEncryption)
     *				Padding: 0
     *				encrypted: 2A69C2FD0A809383EACB7CA16E48C8ABB3E4038A4FA288B9...
     *		CMPCertificate: x509v3PKCert (0)
     *			x509v3PKCert (id-at-commonName=enbroot,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *				signedCertificate
     *					version: v3 (2)
     *					serialNumber : 0x00a1ae2a3b2800db0e
     *					signature (shaWithRSAEncryption)
     *					issuer: rdnSequence: 6 items (id-at-commonName=enbroot,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *					validity
     *						notBefore: utcTime (0)		utcTime: 10-06-03 08:32:55 (UTC)
     *						notAfter: utcTime (0)		utcTime: 11-06-03 08:32:55 (UTC)
     *					subject: rdnSequence: 6 items (id-at-commonName=enbroot,id-at-organizationalUnitName=lte,id-at-organizationName=wl,id-at-localityName=qc,id-at-stateOrProvinceName=sh,id-at-countryName=cn)
     *					subjectPublicKeyInfo
     *						algorithm (rsaEncryption)
     *						Padding: 0
     *						subjectPublicKey: 30818902818100B52E31F83920EAC770A9E516A953E5F162...
     *					extensions: 3 items
     *						Extension (id-ce-subjectKeyIdentifier)
     *							Extension Id: 2.5.29.14 (id-ce-subjectKeyIdentifier)
     *							SubjectKeyIdentifier: 33C563BBADA99901734613B70E24014F5145E3C7
     *						Extension (id-ce-basicConstraints)
     *							Extension Id: 2.5.29.19 (id-ce-basicConstraints)
     *							BasicConstraintsSyntax
     *								cA: True
     *						Extension (id-ce-keyUsage)
     *							Extension Id: 2.5.29.15 (id-ce-keyUsage)
     *							Padding: 1
     *							KeyUsage: F6 (digitalSignature, contentCommitment, keyEncipherment, dataEncipherment, keyCertSign, cRLSign)
     *				algorithmIdentifier (shaWithRSAEncryption)
     *				Padding: 0
     *				encrypted: 7BD35EC086CBC4C2BF3DC891FD60341D6E3938B8ED26C4AD...
     */
    static byte[] telefonica2 = Base64
            .decode(("MIILtTCCARECAQKkVDBSMQswCQYDVQQGEwJjbjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnFjMQsw"
                    + "CQYDVQQKEwJ3bDEMMAoGA1UECxMDbHRlMQ4wDAYDVQQDEwVlbmJjYaRuMGwxCzAJBgNVBAYTAkNO"
                    + "MQ8wDQYDVQQKEwZIdWF3ZWkxJjAkBgNVBAsTHVdpcmVsZXNzIE5ldHdvcmsgUHJvZHVjdCBMaW5l"
                    + "MSQwIgYDVQQDExsyMTAzMDUzMzYxMDAwMDAwMDAxMiBlTm9kZUKgERgPMjAxMTAyMjIxNzU2MDFa"
                    + "oQ8wDQYJKoZIhvcNAQEFBQCkBgQERucoiKUSBBATrD26fYGHOwYhgJaiquBEpgYEBCGfBFKhggVD"
                    + "MIIFP6GCAmgwggJkMIICYDCCAcmgAwIBAgIJALJSzpNbH+s6MA0GCSqGSIb3DQEBBQUAMFQxCzAJ"
                    + "BgNVBAYTAmNuMQswCQYDVQQIEwJzaDELMAkGA1UEBxMCcWMxCzAJBgNVBAoTAndsMQwwCgYDVQQL"
                    + "EwNsdGUxEDAOBgNVBAMTB2VuYnJvb3QwHhcNMTAwNjAzMDgzMzI4WhcNMTEwNjAzMDgzMzI4WjBS"
                    + "MQswCQYDVQQGEwJjbjELMAkGA1UECBMCc2gxCzAJBgNVBAcTAnFjMQswCQYDVQQKEwJ3bDEMMAoG"
                    + "A1UECxMDbHRlMQ4wDAYDVQQDEwVlbmJjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzIwN"
                    + "8oP7/TcXeFpDmXZZlKkeZ4/PAzRancAj6mmdhbeZY+lvgOt/KmQyolu1jPkUUDDy2nxzyuuADAQe"
                    + "C9o6VHgteppQzT2XC75ol5YUc1BtCaU2CD7MmpqFC9NB/UWCP++r1mRPXWzdI/rkhAqudfberNRX"
                    + "ouSmmHXqF0KQY+UCAwEAAaM8MDowHQYDVR0OBBYEFExg23UkAFE/LF9llJj7VRVeIwBFMAwGA1Ud"
                    + "EwQFMAMBAf8wCwYDVR0PBAQDAgH2MA0GCSqGSIb3DQEBBQUAA4GBACppwv0KgJOD6st8oW5IyKuz"
                    + "5AOKT6KIubIDsv8tRUHsodUku1ujedyMY6dzPytNHea87P3nz5Bx4gEUS7ItVmAPS1oCVrzOlrw8"
                    + "Mfd22n7w+OqL4R+9Tf3vyxIzYHCa3cR5ACgLn2p8/iRx7D+IePYz0wnrRjV3RU/JzjGY2pJQMIIC"
                    + "zzCCAssCAgFjMAMCAQAwggK+oIICujCCArYwggIfoAMCAQICBPeOwkYwDQYJKoZIhvcNAQEFBQAw"
                    + "UjELMAkGA1UEBhMCY24xCzAJBgNVBAgTAnNoMQswCQYDVQQHEwJxYzELMAkGA1UEChMCd2wxDDAK"
                    + "BgNVBAsTA2x0ZTEOMAwGA1UEAxMFZW5iY2EwHhcNMTEwMjIyMTc1NjAxWhcNMTEwNjAzMDgzMzI4"
                    + "WjAmMSQwIgYDVQQDDBsyMTAzMDUzMzYxMDAwMDAwMDAxMiBlTm9kZUIwggEiMA0GCSqGSIb3DQEB"
                    + "AQUAA4IBDwAwggEKAoIBAQCcK80Hy7DPK4t1BiZo1k8/eMBnQMv72I/Mk9odR1CLaobm2ShjLpRw"
                    + "f9aUkz3RAiCv5ccrqssItaeTTsA9/8X1QPGEKmf0FYznVzgzBIOehK8Uh2o7CxNICKu+RQCxwXc5"
                    + "5bfhGtdlEKayXmNI0Pgy5HJSwNBy3LVT9uPVTiCVB0L5HCPAFgUrYrnzS6AS7P/HidS1+rKO/sUU"
                    + "9jVy3Z7l1D/09uD+2rTqjEwu5Y7nchVFnRbAAJBtQhyvRt2V/CbtaqQckRTnVJ0QOKx9L9LKIrk1"
                    + "h+MRrYP9mIYtERSBTHm4Nzg02N0c7JxD/QvWL3No6jIptp1RkUhN1yCUdpLjAgMBAAGjQTA/MA4G"
                    + "A1UdDwEB/wQEAwIDuDAtBgNVHREBAf8EIzAhgh8yMTAzMDUzMzYxMDAwMDAwMDAxMi5odWF3ZWku"
                    + "Y29tMA0GCSqGSIb3DQEBBQUAA4GBAGS3N6ivCifLGdZtM1fTW2Ls/qJsSlict/WtdEVtThyZ51yX"
                    + "50AJsvjmQtduU4Qbj0vOPETlP9+L35j3j5Lo+RRkLFTJ4FSWZzJ6ZZSF5u3eWnMZRF74wrBg32Ip"
                    + "I9g5MA5IvyYdJb45Zcjs07QVZNQXzjBjcESwglCHC3vu4vyooIGEA4GBAHyVEwA05nqeh7BbJGm0"
                    + "/lUjwCE6c6MsGyAV6ticmTbp+BFx6fHGk1tHNNhCcJxQxSdAv9nEsClExrhuXiBSG/SdBmrAs6lh"
                    + "odMrRkMTQO/FooMiwDjRX7zNBGnVHBQYnXY/cGtTIAQWhwhFgBrq3HX31ogkEPOmBsTFeoxzYvxn"
                    + "oYIEzjCCBMowggJgMIIByaADAgECAgkAslLOk1sf6zowDQYJKoZIhvcNAQEFBQAwVDELMAkGA1UE"
                    + "BhMCY24xCzAJBgNVBAgTAnNoMQswCQYDVQQHEwJxYzELMAkGA1UEChMCd2wxDDAKBgNVBAsTA2x0"
                    + "ZTEQMA4GA1UEAxMHZW5icm9vdDAeFw0xMDA2MDMwODMzMjhaFw0xMTA2MDMwODMzMjhaMFIxCzAJ"
                    + "BgNVBAYTAmNuMQswCQYDVQQIEwJzaDELMAkGA1UEBxMCcWMxCzAJBgNVBAoTAndsMQwwCgYDVQQL"
                    + "EwNsdGUxDjAMBgNVBAMTBWVuYmNhMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMjA3yg/v9"
                    + "Nxd4WkOZdlmUqR5nj88DNFqdwCPqaZ2Ft5lj6W+A638qZDKiW7WM+RRQMPLafHPK64AMBB4L2jpU"
                    + "eC16mlDNPZcLvmiXlhRzUG0JpTYIPsyamoUL00H9RYI/76vWZE9dbN0j+uSECq519t6s1Fei5KaY"
                    + "deoXQpBj5QIDAQABozwwOjAdBgNVHQ4EFgQUTGDbdSQAUT8sX2WUmPtVFV4jAEUwDAYDVR0TBAUw"
                    + "AwEB/zALBgNVHQ8EBAMCAfYwDQYJKoZIhvcNAQEFBQADgYEAKmnC/QqAk4Pqy3yhbkjIq7PkA4pP"
                    + "ooi5sgOy/y1FQeyh1SS7W6N53Ixjp3M/K00d5rzs/efPkHHiARRLsi1WYA9LWgJWvM6WvDwx93ba"
                    + "fvD46ovhH71N/e/LEjNgcJrdxHkAKAufanz+JHHsP4h49jPTCetGNXdFT8nOMZjaklAwggJiMIIB"
                    + "y6ADAgECAgkAoa4qOygA2w4wDQYJKoZIhvcNAQEFBQAwVDELMAkGA1UEBhMCY24xCzAJBgNVBAgT"
                    + "AnNoMQswCQYDVQQHEwJxYzELMAkGA1UEChMCd2wxDDAKBgNVBAsTA2x0ZTEQMA4GA1UEAxMHZW5i"
                    + "cm9vdDAeFw0xMDA2MDMwODMyNTVaFw0xMTA2MDMwODMyNTVaMFQxCzAJBgNVBAYTAmNuMQswCQYD"
                    + "VQQIEwJzaDELMAkGA1UEBxMCcWMxCzAJBgNVBAoTAndsMQwwCgYDVQQLEwNsdGUxEDAOBgNVBAMT"
                    + "B2VuYnJvb3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALUuMfg5IOrHcKnlFqlT5fFiKM4D"
                    + "RfpVznugWDrJtKrgr8rf9SoybAPi4JiwYHfWRAjNkutR9/h4KWbcrz1vBpooklEixtPzSUHJ4xfc"
                    + "Rz39AI0bC/qzm2ru9l1qTXMfRA2qydb0Y/Q8m2S+DyJCaiP1eNinny6u4oWxx8A6Y8mLAgMBAAGj"
                    + "PDA6MB0GA1UdDgQWBBQzxWO7ramZAXNGE7cOJAFPUUXjxzAMBgNVHRMEBTADAQH/MAsGA1UdDwQE"
                    + "AwIB9jANBgkqhkiG9w0BAQUFAAOBgQB7017AhsvEwr89yJH9YDQdbjk4uO0mxK2SKowiYNj5BoMk"
                    + "tAyjcA7hgNX00Wg7qLQe9IuoOCy2fdldmP+s7sLouXi1oh7OjOxk50TANQg4V28vPhfdgxAgGowi"
                    + "GCsbCtLscLeYallqTuvg/0O2zZITN5wcoQOjackHjIJg3eAz8A==").getBytes());

}
