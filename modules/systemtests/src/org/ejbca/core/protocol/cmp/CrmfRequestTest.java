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

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CaSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * This test runs in 'normal' CMP mode
 * 
 * @author tomas
 * @version $Id$
 *
 */
public class CrmfRequestTest extends CmpTestCase {
	
    private static final Logger log = Logger.getLogger(CrmfRequestTest.class);

    private static String user = "abc123rry"+new Random().nextLong();
    private static String userDN = "CN="+user+", O=PrimeKey Solutions AB, C=SE";
    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static int caid = 0;
    private static Admin admin;
    private static X509Certificate cacert = null;
    
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

	public CrmfRequestTest(String arg0) throws CertificateEncodingException, CertificateException {
		super(arg0);
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
        CryptoProviderTools.installBCProvider();
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = caAdminSession.getCAInfo(admin, "AdminCA1");
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
        CAInfo cainfo = caAdminSession.getCAInfo(admin, caid);
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
        log.debug("issuerDN: " + issuerDN);
        log.debug("caid: " + caid);
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "normal");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        updatePropertyOnServer(CmpConfiguration.CONFIG_DEFAULTCA, issuerDN);
    }

    public void setUp() throws Exception {
        super.setUp();
        if (keys == null) {
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        }
    }

    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void test01CrmfHttpUnknowUser() throws Exception {
    	log.trace(">test01CrmfHttpUnknowUser");
        // A name that does not exist
        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull(req);
        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        /*
         * FileOutputStream fos = new
         * FileOutputStream("/home/tomas/dev/support/cmp_0_ir"); fos.write(ba);
         * fos.close();
         */
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null);
        checkCmpFailMessage(resp, "User " + user + " not found.", 1, reqId, 7); // Expects a CertificateResponse (reject) message with error FailInfo.INCORRECT_DATA
    	log.trace("<test01CrmfHttpUnknowUser");
    }

    public void test02CrmfHttpOkUser() throws Exception {
    	log.trace(">test02CrmfHttpOkUser");
        // Create a new good user
        createCmpUser();

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, false, null, null, null, null);
        assertNotNull(req);
        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, true, null);
        X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertNull("AltNames was not null (" + altNames + ").", altNames);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(confirm);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpPKIConfirmMessage(userDN, cacert, resp);

        // Now revoke the bastard!
        PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), cacert, nonce, transid, true);
        assertNotNull(rev);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(rev);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpFailMessage(resp, "No PKI protection to verify.", 23, reqId, 1);
    	log.trace("<test02CrmfHttpOkUser");
    }

    public void test03BlueXCrmf() throws Exception {
    	log.trace(">test03BlueXCrmf");
        byte[] resp = sendCmpHttp(bluexir, 200);
        assertNotNull(resp);
        checkCmpPKIErrorMessage(resp, "C=NL,O=A.E.T. Europe B.V.,OU=Development,CN=Test CA 1", "", 512, null); // 4=BAD_REQUEST, 512=BAD_POP, 64=WRONG_AUTHORITY
    	log.trace("<test03BlueXCrmf");
    }

    public void test04BadBytes() throws Exception {
    	log.trace(">test04BadBytes");
        byte[] msg = bluexir;
        // Change some bytes to make the message bad
        msg[10] = 0;
        msg[15] = 0;
        msg[22] = 0;
        msg[56] = 0;
        msg[88] = 0;
        // Bad request will return HTTP 400 (bad request)
        byte[] resp = sendCmpHttp(msg, 400);
        assertNull(resp);
    	log.trace("<test04BadBytes");
    }

    public void testZZZCleanUp() throws Exception {
    	log.trace(">testZZZCleanUp");
    	boolean cleanUpOk = true;
		try {
			userAdminSession.deleteUser(admin, "cmptest");
		} catch (NotFoundException e) {
			// A test probably failed before creating the entity
        	log.error("Failed to delete user \"cmptest\".");
        	cleanUpOk = false;
		}
		if (!configurationSession.restoreConfiguration()) {
			cleanUpOk = false;
		}
        assertTrue("Unable to clean up properly.", cleanUpOk);
    	log.trace("<testZZZCleanUp");
    }

    //
    // Private helper methods
    //

    //
    // Private helper methods
    //
    private void createCmpUser() throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
            EjbcaException, FinderException {
        // Make user that we know...
        boolean userExists = false;
        userDN = "C=SE,O=PrimeKey,CN=cmptest";
        UserDataVO user = new UserDataVO("cmptest", userDN, caid, null, "cmptest@primekey.se", SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        try {
            userAdminSession.addUser(admin, user, false);
            // usersession.addUser(admin,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: cmptest, foo123, " + userDN);
        } catch (Exception e) {
            userExists = true;
        }

        if (userExists) {
            log.debug("User cmptest already exists.");
            userAdminSession.changeUser(admin, user, false);
            userAdminSession.setUserStatus(admin, "cmptest", UserDataConstants.STATUS_NEW);
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
