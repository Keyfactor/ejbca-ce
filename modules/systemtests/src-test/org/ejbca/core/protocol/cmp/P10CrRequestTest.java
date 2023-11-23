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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.util.EjbRemoteHelper;
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

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * This test runs in CMP client mode.
 *
 * You can run this test against a CMP Proxy instead of directly to the CA by setting the system property httpCmpProxyURL,
 * for example "-DhttpCmpProxyURL=http://proxy-ip:8080/cmpProxy-6.4.0", which can be set in Run Configurations if running the
 * test from Eclipse.
 * Adjusting the properties in cmpProxy.properties could be required, for example set the two below:
 * 
 * cmp.backend.http.url=http://proxy-ip:8080/ejbca/publicweb/cmp/CrmfRequestTestCmpConfigAlias
 * cmp.backend.http.appendalias=false
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class P10CrRequestTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(P10CrRequestTest.class);

    private static final String USER = "abc123rry" + new Random().nextLong();
    private static final X500Name USER_DN = new X500Name("CN=" + USER + ", O=PrimeKey Solutions AB, C=SE");
    private static final String ISSUER_DN = "CN=TestCA";
    private final KeyPair keys;
    private final int caid;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private static final String CMP_ALIAS = "CrmfRequestTestCmpConfigAlias";
    private static final int P10CR_CERT_REQ_ID = 0; //cerReqId is undefined for p10cr request types, setting it to zero according to openssl

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    public P10CrRequestTest() throws Exception {
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
        this.cmpConfiguration.addAlias(CMP_ALIAS);
        this.cmpConfiguration.setRAMode(CMP_ALIAS, false);
        this.cmpConfiguration.setResponseProtection(CMP_ALIAS, "signature");
        this.cmpConfiguration.setCMPDefaultCA(CMP_ALIAS, ISSUER_DN);
        this.cmpConfiguration.setAuthenticationModule(CMP_ALIAS, CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(CMP_ALIAS, "foo123");
        this.cmpConfiguration.setExtractUsernameComponent(CMP_ALIAS, "CN");
        this.cmpConfiguration.setRACertProfile(CMP_ALIAS, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRAEEProfile(CMP_ALIAS, String.valueOf(eepDnOverrideId));
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        CaTestUtils.removeCa(ADMIN, testx509ca.getCAInfo());
        try {
            this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
        } catch (NoSuchEndEntityException e) {
            // A test probably failed before creating the entity
            log.debug("Failed to delete USER \"cmptest\".");
        }
        this.cmpConfiguration.removeAlias(CMP_ALIAS);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void p10CrHttpUnknowUser() throws Exception {
        log.trace(">p10CrRequestHttpUnknowUser");
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        PKIMessage req = genP10CrCertReq(ISSUER_DN, USER_DN, this.keys, this.cacert, nonce, transid, false, null, new Date(), new Date(), null, null, null, false);
        assertNotNull(req);
        
        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
        
        checkCmpResponseGeneral(resp, ISSUER_DN, USER_DN, this.cacert, nonce, transid, true, null,
                PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
        
        // Expect a CertificateResponse (reject) message with error FailInfo.INCORRECT_DATA
        checkCmpFailMessage(resp, "Wrong username or password", PKIBody.TYPE_CERT_REP, P10CR_CERT_REQ_ID, PKIFailureInfo.incorrectData);
        log.trace("<p10CrRequestHttpUnknowUser");
    }

    @Test
    public void p10CrHttpUnknowUserSignedMessage() throws Exception {
        log.trace(">p10CrHttpUnknowUserSignedMessage");
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();
        PKIMessage req = genP10CrCertReq(ISSUER_DN, USER_DN, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null, false);
        assertNotNull(req);
        X509Certificate signCert = CertTools.genSelfCert("CN=CMP Sign Test", 3650, null, this.keys.getPrivate(), this.keys.getPublic(), "SHA256WithRSA", false);
        ArrayList<Certificate> signCertColl = new ArrayList<>();
        signCertColl.add(signCert);

        byte[] ba = CmpMessageHelper.signPKIMessage(req, signCertColl, this.keys.getPrivate(), CMSSignedGenerator.DIGEST_SHA1, BouncyCastleProvider.PROVIDER_NAME);
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, USER_DN, this.cacert, nonce, transid, true, null,
                PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), false);
        // Expect a CertificateResponse (reject) message with error FailInfo.INCORRECT_DATA
        checkCmpFailMessage(resp, "Wrong username or password", PKIBody.TYPE_CERT_REP, P10CR_CERT_REQ_ID, PKIFailureInfo.incorrectData);
        log.trace("<p10CrHttpUnknowUserSignedMessage");
    }

    @Test
    public void p10CrHttpOkUser() throws Exception {
        log.trace(">p10CrHttpOkUser");
        // Create a new good USER
        X500Name userDN = createCmpUser("cmptest", "foo123", "C=SE,O=PrimeKey,CN=cmptest", true, this.caid, -1, -1);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genP10CrCertReq(ISSUER_DN, userDN, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null, false);
        assertNotNull(req);

        // Since the RegTokenPwd is not supported by p10cr, we need this hmac protection here
        req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);

        byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null,
                PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
        //Request id not applicable for pc10cr requests!
        X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, userDN, this.cacert, resp, P10CR_CERT_REQ_ID);
        
        String altNames = DnComponents.getSubjectAlternativeName(cert);
        
        assertNull("AltNames was not null (" + altNames + ").", altNames);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, P10CR_CERT_REQ_ID, null);
        ba = CmpMessageHelper.pkiMessageToByteArray(confirm);
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, CMP_ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null,
                PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        // Now revoke the bastard!
        PKIMessage rev = genRevReq(ISSUER_DN, userDN, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
        byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
        // Send request and receive response
        resp = sendCmpHttp(barev, 200, CMP_ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, false, null,
            PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
        checkCmpFailMessage(resp, "PKI Message is not authenticated properly. No HMAC protection was found.", PKIBody.TYPE_ERROR, P10CR_CERT_REQ_ID,
                                PKIFailureInfo.badRequest);

        //
        // Try again, this time setting implicitConfirm in the header, expecting the server to reply with implicitConfirm as well
        userDN = createCmpUser("cmptest", "foo123", "C=SE,O=PrimeKey,CN=cmptest", true, this.caid, -1, -1);
        nonce = CmpMessageHelper.createSenderNonce();
        transid = CmpMessageHelper.createSenderNonce();
        DEROctetString keyId = new DEROctetString("primekey".getBytes());
        req = genP10CrCertReq(ISSUER_DN, userDN, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, keyId, true);
        assertNotNull(req);

        req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);
        
        ba = CmpMessageHelper.pkiMessageToByteArray(req);
        // Send request and receive response
        resp = sendCmpHttp(ba, 200, CMP_ALIAS);
        checkCmpResponseGeneral(resp, ISSUER_DN, userDN, this.cacert, nonce, transid, true, null,
                PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), true, "primekey", false);
        cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, userDN, this.cacert, resp, P10CR_CERT_REQ_ID);
        altNames = DnComponents.getSubjectAlternativeName(cert);
        assertNull("AltNames was not null (" + altNames + ").", altNames);

        log.trace("<p10CrHttpOkUser");
        
    }

    @Test
    public void p10CrSubjectDNSerialnumber() throws Exception {
        log.trace(">p10CrSubjectDNSerialnumber");
        // Create a new good USER
        String cmpsntestUsername = "cmpsntest";
        String cmpsntest2Username = "cmpsntest2";
        final X500Name userDN1 = createCmpUser(cmpsntestUsername, "foo123", "C=SE,SN=12234567,CN=cmpsntest", true, this.caid, -1, -1);

        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            PKIMessage req = genP10CrCertReq(ISSUER_DN, userDN1, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null, false);
            assertNotNull(req);

            // Since the RegTokenPwd is not supported by p10cr, we need this hmac protection here
            req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);
            
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, true, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, userDN1, this.cacert, resp, P10CR_CERT_REQ_ID);

            // Now revoke the certificate!
            PKIMessage rev = genRevReq(ISSUER_DN, userDN1, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            assertNotNull(rev);
            byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200,CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN1, this.cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            int revStatus = checkRevokeStatus(ISSUER_DN, CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);

            // Create another USER with the subjectDN serialnumber spelled "SERIALNUMBER" instead of "SN"
            KeyPair keys2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);

            final X500Name userDN2 = createCmpUser(cmpsntest2Username, "foo123", "C=SE,SERIALNUMBER=123456789,CN=cmpsntest2", true, this.caid, -1, -1);
            req = genP10CrCertReq(ISSUER_DN, userDN2, keys2, this.cacert, nonce, transid, false, null, null, null, null, null, null, false);
            assertNotNull(req);

            // Since the RegTokenPwd is not supported by p10cr, we need this hmac protection here
            req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);

            ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN2, this.cacert, nonce, transid, true, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, userDN2, this.cacert, resp, P10CR_CERT_REQ_ID);

            // Now revoke this certificate too
            rev = genRevReq(ISSUER_DN, userDN2, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            assertNotNull(rev);
            barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, userDN2, this.cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            revStatus = checkRevokeStatus(ISSUER_DN, CertTools.getSerialNumber(cert));
            assertNotEquals("Revocation request failed to revoke the certificate", RevokedCertInfo.NOT_REVOKED, revStatus);
        } finally {
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, cmpsntestUsername);
            } catch (NoSuchEndEntityException e) {} // NOOMD;
            try {
                this.endEntityManagementSession.deleteUser(ADMIN, cmpsntest2Username);
            } catch (NoSuchEndEntityException e) {} // NOOMD;
        }
        log.trace("<p10CrSubjectDNSerialnumber");
    }

    @Test
    public void p10CrEscapedCharsInDN() throws Exception {
        log.trace(">p10CrEscapedCharsInDN");

        this.cmpConfiguration.setExtractUsernameComponent(CMP_ALIAS, "DN");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // --------------- Send a CRMF request with the whole DN as username with escapable characters --------------- //
        final String sRequestName = "CN=another\0nullguy%00<do>";
        // Create a new good USER
        final X500Name requestName = createCmpUser(sRequestName, "foo123", sRequestName, false, this.caid, -1, -1);

        try {
            PKIMessage req = genP10CrCertReq(ISSUER_DN, requestName, this.keys, this.cacert, nonce, transid, false, null, null, null, null, null, null, false);
            assertNotNull(req);
            
            // Since the RegTokenPwd is not supported by p10cr, we need this hmac protection here
            req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);

            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, requestName, this.cacert, nonce, transid, true, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, new X500Name(StringTools.strip(sRequestName)), this.cacert, resp, P10CR_CERT_REQ_ID);
            assertNotNull(cert);

            // Now revoke the bastard!
            PKIMessage rev = genRevReq(ISSUER_DN, requestName, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, requestName, this.cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
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
            PKIMessage req = genP10CrCertReq(ISSUER_DN, dn, key2, this.cacert, nonce, transid, false, null, null, null, null, null, null, false);
            assertNotNull(req);
            
            // Since the RegTokenPwd is not supported by p10cr, we need this hmac protection here
            req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);
            
            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, dn, this.cacert, nonce, transid, true, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, dn, this.cacert, resp, P10CR_CERT_REQ_ID);
            assertNotNull(cert);

            // Now revoke the bastard!
            PKIMessage rev = genRevReq(ISSUER_DN, dn, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
            assertNotNull(rev);
            rev = protectPKIMessage(rev, false, "foo123", 567);
            byte[] barev = CmpMessageHelper.pkiMessageToByteArray(rev);
            // Send request and receive response
            resp = sendCmpHttp(barev, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, ISSUER_DN, dn, this.cacert, nonce, transid, false, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
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
        log.trace("<p10CrEscapedCharsInDN");
    }

    @Test
    public void p10CrIncludingCertChainInSignedCMPResponse() throws Exception {
        log.trace(">p10CrIncludingCertChainInSignedCMPResponse");

        //---------- Create SubCA signed by testx509ca (rootCA) ------------- //
        String subcaDN = "CN=SubTestCA";
        int subcaID = subcaDN.hashCode();
        int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(ADMIN, null, true, false, subcaDN, "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        final String username = "cmptest";
        try {
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
            final List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>(2);
            extendedCaServices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            String caname = DnComponents.getPartFromDN(subcaDN, "CN");
            boolean ldapOrder = !DnComponents.isDNReversed(subcaDN);
            X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(subcaDN, caname, CAConstants.CA_ACTIVE, CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA,
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
                    SecConst.TOKEN_SOFT_PEM, null);
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

            PKIMessage req = genP10CrCertReq(subcaDN, userDN, this.keys, subcaCert, nonce, transid, false, null, null, null, null, null, null, false);
            assertNotNull(req);
            
            // Since the RegTokenPwd is not supported by p10cr, we need this hmac protection here
            req = protectPKIMessage(req, false, "foo123", "mykeyid", 567);

            byte[] ba = CmpMessageHelper.pkiMessageToByteArray(req);
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200, CMP_ALIAS);
            checkCmpResponseGeneral(resp, subcaDN, userDN, subcaCert, nonce, transid, true, null,
                    PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), false);
            final X509Certificate cert = checkCmpCertRepMessage(cmpConfiguration, CMP_ALIAS, userDN, subcaCert, resp, P10CR_CERT_REQ_ID);
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
            CaTestUtils.removeCa(ADMIN, this.caSession.getCAInfo(ADMIN, subcaID));
        }
        log.trace("<p10CrIncludingCertChainInSignedCMPResponse");
    }
}
