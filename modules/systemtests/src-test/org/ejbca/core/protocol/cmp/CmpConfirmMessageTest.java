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

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.certificates.ca.CA;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.junit.util.CryptoTokenRule;
import org.cesecore.junit.util.CryptoTokenTestRunner;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

import static org.junit.Assert.assertNotNull;

/**
 * This test runs in 'normal' CMP mode
 * 
 * @version $Id$
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(CryptoTokenTestRunner.class)
public class CmpConfirmMessageTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRequestTest.class);

    private static final String user = "TestUser";
    private static final X500Name userDN = new X500Name("CN=" + user + ", O=PrimeKey Solutions AB, C=SE");
    private final X509Certificate cacert;
    private final CA testx509ca;
    private final CmpConfiguration cmpConfiguration;
    private static final String cmpAlias = "CmpConfirmMessageTestConfAlias";

    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @ClassRule
    public static CryptoTokenRule cryptoTokenRule = new CryptoTokenRule();
     
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    public CmpConfirmMessageTest() throws Exception {
        this.testx509ca = cryptoTokenRule.createX509Ca();
        this.cacert = (X509Certificate) this.testx509ca.getCACertificate();
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
    }
    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        //this.caSession.addCA(ADMIN, this.testx509ca);
        log.debug("this.testx509ca.getSubjectDN(): " + this.testx509ca.getSubjectDN());
        log.debug("caid: " + this.testx509ca.getCAId());
        
        this.cmpConfiguration.addAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        cryptoTokenRule.cleanUp();
        this.cmpConfiguration.removeAlias(cmpAlias);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }
    
    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }




    /**
     * This test sends a CmpConfirmMessage and expects a successful CmpConfirmResponse message
     * signed using the CA specified as recipient in the request.
     * @throws Exception
     */
    @Test
    public void test01ConfRespSignedByRecepient() throws Exception {
        log.trace(">test01ConfRespSignedByRecepient");

        this.cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        this.cmpConfiguration.setCMPDefaultCA(cmpAlias, "");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, 0, null);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bao, ASN1Encoding.DER);
        dOut.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, this.testx509ca.getSubjectDN(), userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        log.trace("<test01ConfRespSignedByRecepient");
    }
    
    /**
     * This test sends a CmpConfirmMessage and expects a successful CmpConfirmResponse message
     * signed using the CA set in cmp.defaultca
     * @throws Exception
     */
    @Test
    public void test02ConfRespSignedByDefaultCA() throws Exception {
        log.trace(">test02ConfRespSignedByDefaultCA");

        this.cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        this.cmpConfiguration.setCMPDefaultCA(cmpAlias, this.testx509ca.getSubjectDN());
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        // the parameter 'null' is to  generate a confirm request for a recipient that does not exist
        PKIMessage confirm = genCertConfirm(userDN, null, nonce, transid, hash, 0, PKCSObjectIdentifiers.sha1WithRSAEncryption);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bao, ASN1Encoding.DER);
        dOut.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, this.testx509ca.getSubjectDN(), userDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        log.trace("<test02ConfRespSignedByDefaultCA");
    }
    
    
    /**
     * This test sends a CmpConfirmMessage and expects a successful CmpConfirmResponse message
     * protected with PBE using the global shared secret set as authentication module parameter 
     * in cmp.authenticationparameter.
     * @throws Exception
     */
    @Test
    public void test03ConfRespPbeProtectedByGlobalSharedSecret() throws Exception {
        log.trace(">test03ConfRespPbeProtected");

        this.cmpConfiguration.setRAMode(cmpAlias, true);
        this.cmpConfiguration.setResponseProtection(cmpAlias, "pbe");
        this.cmpConfiguration.setCMPDefaultCA(cmpAlias, "");
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "password");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, 0, null);
        confirm = protectPKIMessage(confirm, false, "password", 567);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bao, ASN1Encoding.DER);
        dOut.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, this.testx509ca.getSubjectDN(), userDN, this.cacert, nonce, transid, false, "password", null /*response is not signed*/);
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        log.trace("<test03ConfRespPbeProtected");
    }
    
    /**
     * This test sends a CmpConfirmMessage and expects a successful CmpConfirmResponse message
     * protected with PBE using the global shared secret set as authentication module parameter 
     * in cmp.authenticationparameter.
     * @throws Exception
     */
    @Test
    public void test04ConfRespPbeProtectedByCACmpSecret() throws Exception {
        log.trace(">test03ConfRespPbeProtected");

        this.cmpConfiguration.setRAMode(cmpAlias, true);
        this.cmpConfiguration.setResponseProtection(cmpAlias, "pbe");
        this.cmpConfiguration.setCMPDefaultCA(cmpAlias, this.testx509ca.getSubjectDN());
        this.cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(cmpAlias, "-");
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, this.cacert, nonce, transid, hash, 0, null);
        confirm = protectPKIMessage(confirm, false, "foo123", 567);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        ASN1OutputStream dOut = ASN1OutputStream.create(bao, ASN1Encoding.DER);
        dOut.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, this.testx509ca.getSubjectDN(), userDN, this.cacert, nonce, transid, false, "foo123", null /*response is not signed*/);
        checkCmpPKIConfirmMessage(userDN, this.cacert, resp);

        log.trace("<test03ConfRespPbeProtected");
    }

}
