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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.persistence.PersistenceException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
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
 * @author tomas
 * @version $Id$
 */
public class CrmfRATcpRequestTest extends CmpTestCase {
	
    private static final Logger log = Logger.getLogger(CrmfRATcpRequestTest.class);

    private static final String CMP_USERNAME = "cmptest";
    private static final String PBEPASSWORD = "password";
    
    private static String userDN = "CN=tomas1,UID=tomas2,O=PrimeKey Solutions AB,C=SE";
    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static int caid = 0;
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfRATcpRequestTest"));
    private static X509Certificate cacert = null;

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws CertificateEncodingException, CertificateException, CADoesntExistsException, AuthorizationDeniedException {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = caSession.getCAInfo(admin, "AdminCA1");
        if (adminca1 == null) {
            Collection<Integer> caids = caSession.getAvailableCAs(admin);
            Iterator<Integer> iter = caids.iterator();
            while (iter.hasNext()) {
                caid = iter.next().intValue();
            }           
        } else {
                caid = adminca1.getCAId();
        }
        if (caid == 0) {
                assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }               
        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        Collection<Certificate> certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator<Certificate> certiter = certs.iterator();
            Certificate cert = certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                cacert = (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
            }
        } else {
            log.error("NO CACERT for caid " + caid);
        }
        issuerDN = cacert.getIssuerDN().getName();
        // Configure CMP for this test
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBEPASSWORD);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-;-");
        
        if (keys == null) {
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        }
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        boolean cleanUpOk = true;

        if (!configurationSession.restoreConfiguration()) {
            cleanUpOk = false;
        }
        assertTrue("Unable to clean up properly.", cleanUpOk);
    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    @Test
    public void test01CrmfUnknowUser() throws Exception {
        // A name that does not exis
        userDN = "CN=abc123rry5774466, O=PrimeKey Solutions AB, C=SE";

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null);
        checkCmpCertRepMessage(userDN, cacert, resp, reqId);
    }

    @Test
    public void test02CrmfOkUser() throws Exception {

        // Create a new good user
        userDN = "C=SE,O=PrimeKey,CN=cmptest";
        createCmpUser(CMP_USERNAME, userDN);
        try {
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();

            PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null);
            checkCmpCertRepMessage(userDN, cacert, resp, reqId);

            // Send a confirm message to the CA
            String hash = "foo123";
            PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
            assertNotNull(confirm);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(confirm);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpTcp(ba, 5);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
            checkCmpPKIConfirmMessage(userDN, cacert, resp);
        } finally {
            endEntityManagementSession.deleteUser(admin, CMP_USERNAME);
        }
    }

    @Test
    public void test03BlueXCrmf() throws Exception {
        PKIMessage req = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(bluexir)).readObject());
        byte[] resp = sendCmpTcp(bluexir, 5);
        userDN = "CN=Some Common Name"; // we know what it is in this request...
        assertNotNull(resp);
        byte[] senderNonce = req.getHeader().getSenderNonce().getOctets();
        byte[] transId = req.getHeader().getTransactionID().getOctets();
        CertReqMessages ir = (CertReqMessages) req.getBody().getContent();
        int reqId = ir.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue();
        checkCmpResponseGeneral(resp, issuerDN, "CN=Some Common Name", cacert, senderNonce, transId, true, null);
        checkCmpCertRepMessage(userDN, cacert, resp, reqId);
    }

    @Test
    public void test04CrmfUnauthenticated() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);

        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpPKIErrorMessage(resp, issuerDN, userDN, PKIFailureInfo.badMessageCheck, "PKI Message is not athenticated properly. No HMAC protection was found.");
    }

    @Test
    public void test05CrmfUnknownProtection() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, true, PBEPASSWORD, 567);

        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpPKIErrorMessage(resp, issuerDN, userDN, PKIFailureInfo.badMessageCheck, "Could not create CmpPbeVerifyer. Protection algorithm id expected '1.2.840.113533.7.66.13' (passwordBasedMac) but was '1.2.840.113533.7.66.13.7'.");
    }

    /**
     * Try a request with SubjectDN email and special characters.
     * 
     * @throws Exception
     */
    @Test
    public void test06DnEmail() throws Exception {
       try {
        String subjectDN = "C=SE,CN=Göran Strömförare,E=adam@eva.se";
        // createCmpUser("cmptest2", subjectDN);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, subjectDN, null, keys, cacert, nonce, transid, true, null, null, null, null, null, null);
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
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, nonce, transid, true, null);
        checkCmpCertRepMessage(subjectDN, cacert, resp, reqId);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(subjectDN, cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(confirm);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, subjectDN, cacert, nonce, transid, false, null);
        checkCmpPKIConfirmMessage(subjectDN, cacert, resp);
       } finally {
           endEntityManagementSession.deleteUser(admin, "Göran Strömförare");
       }
    }

    //
    // Private helper methods
    //
    private void createCmpUser(String username, String userDN) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            ApprovalException, WaitingForApprovalException, EjbcaException, FinderException, PersistenceException, CADoesntExistsException {
        // Make user that we know...
        boolean userExists = false;
        try {
            endEntityManagementSession.addUser(admin, username, "foo123", userDN, null, "cmptest@primekey.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
            log.debug("created user: " + username + ", foo123, " + userDN);
        } catch (EJBException e) {
            if (e.getCause() instanceof PersistenceException) {
                userExists = true;
            }
        }

        if (userExists) {
            log.debug("User " + username + " already exists.");
            endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
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
