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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * These tests test RA functionality with the CMP protocol, i.e. a "trusted" RA sends CMP messages authenticated using PBE (password based encryption)
 * and these requests are handled by EJBCA without further authentication, end entities are created automatically in EJBCA.
 * 
 * You need a CMP TCP listener configured on port 5587 to run this test. (cmp.tcp.enabled=true, cmp.tcp.portno=5587)
 * 
 * 'ant clean; ant bootstrap' to deploy configuration changes.
 * 
 * @version $Id$
 */
public class CrmfRAPbeTcpRequestTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRAPbeTcpRequestTest.class);

    private static final String PBEPASSWORD = "password";

    /** userDN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations */
    private static final X500Name userDN = new X500Name("C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,CN=cmptest");

    private static final String issuerDN = "CN=TestCA";
    private final KeyPair keys;
    private final int caid;
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private final static String cmpAlias = "tcp";

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    public CrmfRAPbeTcpRequestTest() throws Exception {
        this.keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        this.testx509ca = CaTestUtils.createTestX509CA(issuerDN, null, false, keyusage);
        this.caid = this.testx509ca.getCAId();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        
        this.caSession.addCA(ADMIN, this.testx509ca);
        
        this.configurationSession.backupConfiguration();
        
        // Configure CMP for this test
        if(this.cmpConfiguration.aliasExists(cmpAlias)) {
            this.cmpConfiguration.renameAlias(cmpAlias, "backupTcpAlias");
        }
        this.cmpConfiguration.addAlias(cmpAlias);
        this.cmpConfiguration.setRAMode(cmpAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(cmpAlias, true);
        this.cmpConfiguration.setResponseProtection(cmpAlias, "pbe");
        this.cmpConfiguration.setRACertProfile(cmpAlias, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRAEEProfile(cmpAlias, String.valueOf(eepDnOverrideId));
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "-;" + PBEPASSWORD);
        this.cmpConfiguration.setRACAName(cmpAlias, this.testx509ca.getName());
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        // Configure a Certificate profile (CmpRA) using CP_DN_OVERRIDE_NAME as template and check "Allow validity override".
        final CertificateProfile cp = this.certProfileSession.getCertificateProfile(this.cpDnOverrideId);
        cp.setAllowValidityOverride(true);
        this.certProfileSession.changeCertificateProfile(ADMIN, CP_DN_OVERRIDE_NAME, cp);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        boolean cleanUpOk = true;
        try {
            this.endEntityManagementSession.deleteUser(ADMIN, "cmptest");
        } catch (NoSuchEndEntityException e) {
            // A test probably failed before creating the entity
            log.error("Failed to delete user \"cmptest\".");
            cleanUpOk = false;
        }
        if (!this.configurationSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        CryptoTokenTestUtils.removeCryptoToken(null, this.testx509ca.getCAToken().getCryptoTokenId());
        this.caSession.removeCA(ADMIN, this.caid);
        
        assertTrue("Unable to clean up properly.", cleanUpOk);
        
        this.cmpConfiguration.removeAlias(cmpAlias);
        if(this.cmpConfiguration.aliasExists("backupTcpAlias")) {
            this.cmpConfiguration.renameAlias("backupTcpAlias", cmpAlias);
        }
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Test
    public void test02CrmfTcpOkUser() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
        assertNotNull(req);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        X509Certificate cert = checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
        assertNotNull(cert);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        // Now revoke the bastard using the CMPv2 CRL entry extension!
        PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), this.cacert, nonce, transid, true, null, null);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, PBEPASSWORD, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), this.cacert, resp, true);
        int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
        assertEquals("Revocation reason should be 'unspecified'", RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, reason);

    }


}
