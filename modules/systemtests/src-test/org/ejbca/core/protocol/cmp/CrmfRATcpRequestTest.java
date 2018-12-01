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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * You need a CMP TCP listener configured on port 5587 to run this test.
 * (cmp.tcp.enabled=true, cmp.tcp.portno=5587)
 * 
 * 'ant clean; ant bootstrap' to deploy configuration changes.
 * 
 * @version $Id$
 */
public class CrmfRATcpRequestTest extends CmpTestCase {
	
    private static final Logger log = Logger.getLogger(CrmfRATcpRequestTest.class);

    private static final String CMP_USERNAME = "cmptest";
    private static final String PBEPASSWORD = "password";
    
    final private static X500Name userDN = new X500Name("CN=Some Common Name"); // we know what it is in this request...
    private static final String issuerDN = "CN=TestCA";
    final private KeyPair keys;
    final private int caid;
    final private X509Certificate cacert;
    final private CA testx509ca;
    final private CmpConfiguration cmpConfiguration;
    final private String cmpAlias = "tcp";


    final private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    final private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    public CrmfRATcpRequestTest() throws Exception {
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
        if(this.cmpConfiguration.aliasExists(this.cmpAlias)) {
            this.cmpConfiguration.renameAlias(this.cmpAlias, "backupTcpAlias");
        }
        this.cmpConfiguration.addAlias(this.cmpAlias);
        this.cmpConfiguration.setRAMode(this.cmpAlias, true);
        this.cmpConfiguration.setAllowRAVerifyPOPO(this.cmpAlias, true);
        this.cmpConfiguration.setResponseProtection(this.cmpAlias, "signature");
        this.cmpConfiguration.setRAEEProfile(this.cmpAlias, String.valueOf(eepDnOverrideId));
        this.cmpConfiguration.setRACertProfile(this.cmpAlias, CP_DN_OVERRIDE_NAME);
        this.cmpConfiguration.setRACAName(this.cmpAlias, "TestCA");
        this.cmpConfiguration.setAuthenticationModule(this.cmpAlias, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        this.cmpConfiguration.setAuthenticationParameters(this.cmpAlias, "-;" + PBEPASSWORD);
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        this.cmpConfiguration.removeAlias(this.cmpAlias);
        if(this.cmpConfiguration.aliasExists("backupTcpAlias")) {
            this.cmpConfiguration.renameAlias("backupTcpAlias", this.cmpAlias);
        }
        this.globalConfigurationSession.saveConfiguration(ADMIN, this.cmpConfiguration);
        
        boolean cleanUpOk = true;
        if (!this.configurationSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        assertTrue("Unable to clean up properly.", cleanUpOk);
        
        CryptoTokenTestUtils.removeCryptoToken(null, this.testx509ca.getCAToken().getCryptoTokenId());
        this.caSession.removeCA(ADMIN, this.caid);
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    @Test
    public void test01CrmfUnknowUser() throws Exception {
        // A name that does not exis
        final X500Name dn = new X500Name("CN=abc123rry5774466, O=PrimeKey Solutions AB, C=SE");

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, dn, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, dn, this.cacert, nonce, transid, true, null,PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpCertRepMessage(dn, this.cacert, resp, reqId);
    }

    @Test
    public void test02CrmfOkUser() throws Exception {

        // Create a new good user
        final X500Name dn = new X500Name("C=SE,O=PrimeKey,CN=cmptest");
        createCmpUser(CMP_USERNAME, dn.toString());
        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            PKIMessage one = genCertReq(issuerDN, dn, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

            CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
            int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
            assertNotNull(req);
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpTcp(ba, 5);
            checkCmpResponseGeneral(resp, issuerDN, dn, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpCertRepMessage(dn, this.cacert, resp, reqId);

            // Send a confirm message to the CA
            String hash = "foo123";
            PKIMessage confirm = genCertConfirm(dn, this.cacert, nonce, transid, hash, reqId);
            assertNotNull(confirm);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(confirm);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpTcp(ba, 5);
            checkCmpResponseGeneral(resp, issuerDN, dn, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
            checkCmpPKIConfirmMessage(dn, this.cacert, resp);
        } finally {
            this.endEntityManagementSession.deleteUser(ADMIN, CMP_USERNAME);
        }
    }

    @Test
    public void test03BlueXCrmf() throws Exception {
        byte[] resp = sendCmpTcp(bluexir, 5);
        assertNotNull(resp);
        // On this (very old) request we can not decode the public key, so we will get an unprotected badRequest message back
        checkCmpPKIErrorMessage(resp, "C=NL,O=A.E.T. Europe B.V.,OU=Development,CN=Test CA 1", new X500Name(new RDN[0]), PKIFailureInfo.badRequest, null);
        // If the message was ok, we could have verified it with the code below
//        byte[] senderNonce = req.getHeader().getSenderNonce().getOctets();
//        byte[] transId = req.getHeader().getTransactionID().getOctets();
//        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
//        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
//        checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, senderNonce, transId, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
//        checkCmpCertRepMessage(userDN, this.cacert, resp, reqId);
    }

    @Test
    public void test04CrmfUnauthenticated() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);

        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIErrorMessage(resp, issuerDN, userDN, PKIFailureInfo.badRequest, "PKI Message is not authenticated properly. No HMAC protection was found.");
    }

    @Test
    public void test05CrmfUnknownProtection() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, true, PBEPASSWORD, 567);

        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIErrorMessage(resp, issuerDN, userDN, PKIFailureInfo.badRequest, "Protection algorithm id expected '1.2.840.113533.7.66.13' (passwordBasedMac) but was '1.2.840.113533.7.66.13.7'.");
    }

    /**
     * Try a request with SubjectDN email and special characters.
     * 
     * @throws Exception
     */
    @Test
    public void test06DnEmail() throws Exception {
       try {
        final X500Name subjectDN = new X500Name("C=SE,CN=Göran Strömförare,E=adam@eva.se");
        // createCmpUser("cmptest2", subjectDN);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, subjectDN, subjectDN, null, this.keys, this.cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, this.cacert, nonce, transid, true, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpCertRepMessage(subjectDN, this.cacert, resp, reqId);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(subjectDN, this.cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(confirm);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, this.cacert, nonce, transid, false, null, PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
        checkCmpPKIConfirmMessage(subjectDN, this.cacert, resp);
       } finally {
           this.endEntityManagementSession.deleteUser(ADMIN, "Göran Strömförare");
       }
    }

    //
    // Private helper methods
    //
    private void createCmpUser(String username, String dn) throws AuthorizationDeniedException, EndEntityProfileValidationException,
            ApprovalException, WaitingForApprovalException, EjbcaException, NoSuchEndEntityException, CADoesntExistsException, IllegalNameException, CertificateSerialNumberException {
        // Make user that we know...
        boolean userExists = false;
        try {
            this.endEntityManagementSession.addUser(ADMIN, username, "foo123", dn, null, "cmptest@primekey.se", false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, this.caid);
            log.debug("created user: " + username + ", foo123, " + dn);
        } catch (EndEntityExistsException e) {
            userExists = true;
        }

        if (userExists) {
            log.debug("User " + username + " already exists.");
            this.endEntityManagementSession.setUserStatus(ADMIN, username, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
    }

    static byte[] bluexir = Base64.decode(("MIICIjCB1AIBAqQCMACkVjBUMQswCQYDVQQGEwJOTDEbMBkGA1UEChMSQS5FLlQu"
            + "IEV1cm9wZSBCLlYuMRQwEgYDVQQLEwtEZXZlbG9wbWVudDESMBAGA1UEAxMJVGVz" + "dCBDQSAxoT4wPAYJKoZIhvZ9B0INMC8EEAK/H7Do+55N724Kdvxm7NcwCQYFKw4D"
            + "AhoFAAICA+gwDAYIKwYBBQUIAQIFAKILBAlzc2xjbGllbnSkEgQQpFpBsonfhnW8" + "ia1otGchraUSBBAyzd3nkKAzcJqGFrDw0jkYoIIBLjCCASowggEmMIIBIAIBADCC"
            + "ARmkJqARGA8yMDA2MDkxOTE2MTEyNlqhERgPMjAwOTA2MTUxNjExMjZapR0wGzEZ" + "MBcGA1UEAwwQU29tZSBDb21tb24gTmFtZaaBoDANBgkqhkiG9w0BAQEFAAOBjgAw"
            + "gYoCgYEAuBgTGPgXrS3AIPN6iXO6LNf5GzAcb/WZhvebXMdxdrMo9+5hw/Le5St/" + "Sz4J93rxU95b2LMuHTg8U6njxC2lZarNExZTdEwnI37X6ep7lq1purq80zD9bFXj"
            + "ougRD5MHfhDUAQC+btOgEXkanoAo8St3cbtHoYUacAXN2Zs/RVcCBAABAAGpLTAr" + "BgNVHREEJDAioCAGCisGAQQBgjcUAgOgEgwQdXBuQGFldGV1cm9wZS5ubIAAoBcD"
            + "FQAy/vSoNUevcdUxXkCQx3fvxkjh6A==").getBytes());

}
