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
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CaSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

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

    private static final String PBEPASSWORD = "password";
    
    private static String userDN = "CN=tomas1,UID=tomas2,O=PrimeKey Solutions AB,C=SE";
    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static int caid = 0;
    private static final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    private static X509Certificate cacert = null;

    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    
	public CrmfRATcpRequestTest(String arg0) throws CertificateEncodingException, CertificateException {
		super(arg0);
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
        // Configure CMP for this test
        updatePropertyOnServer(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        updatePropertyOnServer(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBEPASSWORD);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "EMPTY");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ENDUSER");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, "AdminCA1");
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

    public void test01CrmfUnknowUser() throws Exception {
        // A name that does not exis
        userDN = "CN=abc123rry5774466, O=PrimeKey Solutions AB, C=SE";

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
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

    public void test02CrmfOkUser() throws Exception {

        // Create a new good user
        userDN = "C=SE,O=PrimeKey,CN=cmptest";
        createCmpUser("cmptest", userDN);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
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
    }

    public void test03BlueXCrmf() throws Exception {
        PKIMessage req = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(bluexir)).readObject());
        byte[] resp = sendCmpTcp(bluexir, 5);
        userDN = "CN=Some Common Name"; // we know what it is in this request...
        assertNotNull(resp);
        byte[] senderNonce = req.getHeader().getSenderNonce().getOctets();
        byte[] transId = req.getHeader().getTransactionID().getOctets();
        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        checkCmpResponseGeneral(resp, issuerDN, "CN=Some Common Name", cacert, senderNonce, transId, true, null);
        checkCmpCertRepMessage(userDN, cacert, resp, reqId);
    }

    public void test04CrmfUnauthenticated() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage req = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);

        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpPKIErrorMessage(resp, issuerDN, userDN, 2, "Received an unathenticated message in RA mode.");
    }

    public void test05CrmfUnknownProtection() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, true, PBEPASSWORD, 567);

        assertNotNull(req);
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpTcp(ba, 5);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, null);
        checkCmpPKIErrorMessage(resp, issuerDN, userDN, 2, "Received CMP message with unknown protection alg: 1.2.840.113533.7.66.13.7.");
    }

    /**
     * Try a request with SubjectDN email and special characters.
     * 
     * @throws Exception
     */
    public void test06DnEmail() throws Exception {
        String subjectDN = "C=SE,CN=Göran Strömförare,E=adam@eva.se";
        // createCmpUser("cmptest2", subjectDN);

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, subjectDN, null, keys, cacert, nonce, transid, true, null, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
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
		try {
			userAdminSession.deleteUser(admin, "Some Common Name");
		} catch (NotFoundException e) {
			// A test probably failed before creating the entity
        	log.error("Failed to delete user \"Some Common Name\".");
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
    private void createCmpUser(String username, String userDN) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            ApprovalException, WaitingForApprovalException, EjbcaException, FinderException {
        // Make user that we know...
        boolean userExists = false;
        try {
            userAdminSession.addUser(admin, username, "foo123", userDN, null, "cmptest@primekey.se", false, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, caid);
            log.debug("created user: " + username + ", foo123, " + userDN);
        } catch (EJBException e) {
            if (e.getCause() instanceof PersistenceException) {
                userExists = true;
            }
        }

        if (userExists) {
            log.debug("User " + username + " already exists.");
            userAdminSession.setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
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
