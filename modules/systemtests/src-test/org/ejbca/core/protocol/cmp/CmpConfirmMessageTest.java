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

package org.ejbca.core.protocol.cmp;

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.keys.token.CryptoTokenManagementSessionTest;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test runs in 'normal' CMP mode
 * 
 * @version $Id: CrmfRequestTest.java 17527 2013-08-27 12:07:19Z aveen4711 $
 * 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CmpConfirmMessageTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRequestTest.class);

    private static AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfRequestTest"));

    private static String user = "TestUser";
    private static String userDN = "CN=" + user + ", O=PrimeKey Solutions AB, C=SE";
    private static String issuerDN = "CN=TestCA";
    private static int caid = 0;
    private static X509Certificate cacert = null;
    private CA testx509ca;
    private CmpConfiguration cmpConfiguration;
    private String cmpAlias = "CmpConfirmMessageTestCmpConfigAlias";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws CertificateEncodingException, CertificateException, CADoesntExistsException, AuthorizationDeniedException {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();

        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaSessionTest.createTestX509CA(issuerDN, null, false, keyusage);
        caid = testx509ca.getCAId();
        cacert = (X509Certificate) testx509ca.getCACertificate();
        caSession.addCA(admin, testx509ca);
        
        log.debug("issuerDN: " + issuerDN);
        log.debug("caid: " + caid);
        
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.CMPConfigID);
        cmpConfiguration.addAlias(cmpAlias);
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        CryptoTokenManagementSessionTest.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, caid);

        cmpConfiguration.removeAlias(cmpAlias);
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);
    }
    
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

        cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        cmpConfiguration.setCMPDefaultCA(cmpAlias, "");
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, 0);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, cacert, resp);

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

        cmpConfiguration.setResponseProtection(cmpAlias, "signature");
        cmpConfiguration.setCMPDefaultCA(cmpAlias, issuerDN);
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, null, nonce, transid, hash, 0);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, cacert, resp);

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

        cmpConfiguration.setRAMode(cmpAlias, true);
        cmpConfiguration.setResponseProtection(cmpAlias, "pbe");
        cmpConfiguration.setCMPDefaultCA(cmpAlias, "");
        cmpConfiguration.setAuthenticationModule(cmpAlias, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(cmpAlias, "password");
        globalConfigurationSession.saveConfiguration(admin, cmpConfiguration, Configuration.CMPConfigID);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, 0);
        confirm = protectPKIMessage(confirm, false, "password", 567);
        assertNotNull(confirm);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(confirm);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200, cmpAlias);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, "password", PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(userDN, cacert, resp);

        log.trace("<test03ConfRespPbeProtected");
    }

}
