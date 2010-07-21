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
import java.io.File;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.EJB;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.keystore.KeyTools;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * These tests test RA functionality with the CMP protocol, i.e. a "trusted" RA
 * sends CMP messages authenticated using PBE (password based encryption) and
 * these requests are handled by EJBCA without further authentication, end
 * entities are created automatically in EJBCA.
 * 
 * 'ant clean; ant bootstrap' to deploy configuration changes.
 * 
 * @author tomas
 * @version $Id: CrmfRAPbeRequestTest.java 9435 2010-07-14 15:18:39Z mikekushner
 *          $
 */
public class CrmfRAPbeRequestTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRAPbeRequestTest.class);

    private static final String PBEPASSWORD = "password";
    private static final String APPROVINGADMINNAME = "superadmin";
    private static final String CPNAME = CrmfRAPbeRequestTest.class.getName();
    private static final String EEPNAME = CrmfRAPbeRequestTest.class.getName();

    /**
     * userDN of user used in this test, this contains special, escaped,
     * characters to test that this works with CMP RA operations
     */
    private static String userDN = "C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,CN=cmptest";

    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;

    private static int caid = 0;
    private static final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    private static X509Certificate cacert = null;

    @EJB
    private ApprovalSessionRemote approvalSessionRemote;

    @EJB
    private CAAdminSessionRemote caAdminSession;

    @EJB
    private CertificateStoreSessionRemote certificateStoreSession;

    @EJB
    private ConfigurationSessionRemote configurationSession;

    @EJB
    private RaAdminSessionRemote raAdminSession;
    
    @EJB
    private UserAdminSessionRemote userAdminSession;

    public CrmfRAPbeRequestTest(String arg0) throws RemoteException, CertificateException {
        super(arg0);
        CryptoProviderTools.installBCProvider();
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = caAdminSession.getCAInfo(admin, "AdminCA1");
        if (adminca1 == null) {
            Collection caids = caAdminSession.getAvailableCAs(admin);
            Iterator iter = caids.iterator();
            while (iter.hasNext()) {
                caid = ((Integer) iter.next()).intValue();
            }
        } else {
            caid = adminca1.getCAId();
        }
        if (caid == 0) {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        CAInfo cainfo = caAdminSession.getCAInfo(admin, caid);
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            X509Certificate cert = (X509Certificate) certiter.next();
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
        configurationSession.updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
        configurationSession.updateProperty(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
        configurationSession.updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        configurationSession.updateProperty(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, "password");
        configurationSession.updateProperty(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, CPNAME);
        configurationSession.updateProperty(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, EEPNAME);
        configurationSession.updateProperty(CmpConfiguration.CONFIG_RACANAME, cainfo.getName());
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        if (certificateStoreSession.getCertificateProfile(admin, CPNAME) == null) {
            CertificateProfile cp = new EndUserCertificateProfile();
            cp.setAllowValidityOverride(true);
            try { // TODO: Fix this better
                certificateStoreSession.addCertificateProfile(admin, CPNAME, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
            }
        }
        int cpId = certificateStoreSession.getCertificateProfileId(admin, CPNAME);
        if (raAdminSession.getEndEntityProfile(admin, EEPNAME) == null) {
            // Configure an EndEntity profile (CmpRA) with allow CN, O, C in DN
            // and rfc822Name (uncheck 'Use entity e-mail field' and check
            // 'Modifyable'), MS UPN in altNames in the end entity profile.
            EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
            eep.setModifyable(DnComponents.RFC822NAME, 0, true);
            eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field
            // from "email" data
            try {
                raAdminSession.addEndEntityProfile(admin, EEPNAME, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
        }
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

    public void test01CrmfHttpOkUser() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        // We should be able to back date the start time when allow validity
        // override is enabled in the certificate profile
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_WEEK, -1);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notBefore = cal.getTime();
        cal.add(Calendar.DAY_OF_WEEK, 3);
        cal.set(Calendar.MILLISECOND, 0); // Certificates don't use milliseconds
        // in validity
        Date notAfter = cal.getTime();

        // In this we also test validity override using notBefore and notAfter
        // from above
        // In this test userDN contains special, escaped characters to verify
        // that that works with CMP RA as well
        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, notBefore, notAfter);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
        assertNotNull(req);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
        X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
        // Check that validity override works
        assertTrue(cert.getNotBefore().equals(notBefore));
        assertTrue(cert.getNotAfter().equals(notAfter));
        String altNames = CertTools.getSubjectAlternativeName(cert);
        assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
        assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);

        // Send a confirm message to the CA
        String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
        assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD, 567);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(req1);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
        checkCmpPKIConfirmMessage(userDN, cacert, resp);

        // Now revoke the bastard using the CMPv1 reason code!
        PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), cacert, nonce, transid, false);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
        checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, true);
        int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
        assertEquals(reason, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);

        // Create a revocation request for a non existing cert, should fail!
        rev = genRevReq(issuerDN, userDN, new BigInteger("1"), cacert, nonce, transid, true);
        revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
        assertNotNull(revReq);
        bao = new ByteArrayOutputStream();
        out = new DEROutputStream(bao);
        out.writeObject(revReq);
        ba = bao.toByteArray();
        // Send request and receive response
        resp = sendCmpHttp(ba, 200);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
        checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, false);
    }

    public void test03CrmfHttpTooManyIterations() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 10001);
        assertNotNull(req);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        DEROutputStream out = new DEROutputStream(bao);
        out.writeObject(req);
        byte[] ba = bao.toByteArray();
        // Send request and receive response
        byte[] resp = sendCmpHttp(ba, 200);
        assertNotNull(resp);
        assertTrue(resp.length > 0);
        checkCmpFailMessage(resp, "Iteration count can not exceed 10000", 23, reqId, 1); // We
        // expect
        // a
        // FailInfo.BAD_MESSAGE_CHECK
    }

    public void test04RevocationApprovals() throws Exception {
        // Generate random username and CA name
        String randomPostfix = Integer.toString((new Random(new Date().getTime() + 4711)).nextInt(999999));
        String caname = "cmpRevocationCA" + randomPostfix;
        String username = "cmpRevocationUser" + randomPostfix;
        X509CAInfo cainfo = null;
        try {
            // Generate CA with approvals for revocation enabled
            int caID = RevocationApprovalTest.createApprovalCA(admin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession);
            // Get CA cert
            cainfo = (X509CAInfo) caAdminSession.getCAInfo(admin, caID);
            assertNotNull(cainfo);
            X509Certificate newCACert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
            // Create a user and generate the cert
            UserDataVO userdata = new UserDataVO(username, "CN=" + username, cainfo.getCAId(), null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                    SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
            userdata.setPassword("foo123");
            userAdminSession.addUser(admin, userdata, true);
            BatchMakeP12 makep12 = new BatchMakeP12();
            File tmpfile = File.createTempFile("ejbca", "p12");
            makep12.setMainStoreDir(tmpfile.getParent());
            makep12.createAllNew();
            Collection userCerts = certificateStoreSession.findCertificatesByUsername(admin, username);
            assertTrue(userCerts.size() == 1);
            X509Certificate cert = (X509Certificate) userCerts.iterator().next();
            // revoke via CMP and verify response
            byte[] nonce = CmpMessageHelper.createSenderNonce();
            byte[] transid = CmpMessageHelper.createSenderNonce();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            PKIMessage rev = genRevReq(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, nonce, transid, true);
            PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(revReq);
            byte[] ba = bao.toByteArray();
            byte[] resp = sendCmpHttp(ba, 200);
            assertNotNull(resp);
            assertTrue(resp.length > 0);
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, true);
            checkCmpRevokeConfirmMessage(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, resp, true);
            int reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
            // try to revoke one more via CMP and verify error
            nonce = CmpMessageHelper.createSenderNonce();
            transid = CmpMessageHelper.createSenderNonce();
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            rev = genRevReq(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, nonce, transid, true);
            revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            assertNotNull(resp);
            assertTrue(resp.length > 0);
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, true);
            checkCmpFailMessage(resp, "The request is already awaiting approval.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0, ResponseStatus.FAILURE
                    .getIntValue());
            reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
            // Approve revocation and verify success
            Admin approvingAdmin = new Admin((X509Certificate) certificateStoreSession.findCertificatesByUsername(admin, APPROVINGADMINNAME).iterator().next(),
                    APPROVINGADMINNAME, null);
            approveRevocation(admin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_CESSATIONOFOPERATION,
                    ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSessionRemote, cainfo.getCAId());
            // try to revoke the now revoked cert via CMP and verify error
            nonce = CmpMessageHelper.createSenderNonce();
            transid = CmpMessageHelper.createSenderNonce();
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            rev = genRevReq(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, nonce, transid, true);
            revReq = protectPKIMessage(rev, false, PBEPASSWORD, 567);
            assertNotNull(revReq);
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(revReq);
            ba = bao.toByteArray();
            resp = sendCmpHttp(ba, 200);
            assertNotNull(resp);
            assertTrue(resp.length > 0);
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, true);
            checkCmpFailMessage(resp, "Already revoked.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0, ResponseStatus.FAILURE.getIntValue());
        } finally {
            // Delete user
            userAdminSession.deleteUser(admin, username);
            // Nuke CA
            try {
                caAdminSession.revokeCA(admin, cainfo.getCAId(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
            } finally {
                caAdminSession.removeCA(admin, cainfo.getCAId());
            }
        }
    } // test04RevocationApprovals

    public void testZZZCleanUp() throws Exception {
        try {
            userAdminSession.deleteUser(admin, "cmptest");
        } catch (NotFoundException e) {
            // A test probably failed before creating the entity
        }
        raAdminSession.removeEndEntityProfile(admin, EEPNAME);
        certificateStoreSession.removeCertificateProfile(admin, CPNAME);
        configurationSession.restoreConfiguration();
    }

    /**
     *      Find all certificates for a user and approve any outstanding revocation. 
     */
    public int approveRevocation(Admin internalAdmin, Admin approvingAdmin, String username, int reason, int approvalType,
                    CertificateStoreSessionRemote certificateStoreSession, ApprovalSessionRemote approvalSession, int approvalCAID) throws Exception {
        Collection userCerts = certificateStoreSession.findCertificatesByUsername(internalAdmin, username);
        Iterator i = userCerts.iterator();
        int approvedRevocations = 0;
        while ( i.hasNext() ) {
            X509Certificate cert = (X509Certificate) i.next();
            String issuerDN = cert.getIssuerDN().toString();
            BigInteger serialNumber = cert.getSerialNumber();
            boolean isRevoked = certificateStoreSession.isRevoked(issuerDN, serialNumber);
                if ( (reason != RevokedCertInfo.NOT_REVOKED && !isRevoked )
                            || (reason == RevokedCertInfo.NOT_REVOKED && isRevoked) )  {
                            int approvalID;
                            if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
                                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuerDN);
                            } else {
                                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null);
                            }
                            Query q = new Query(Query.TYPE_APPROVALQUERY);
                            q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
                            ApprovalDataVO approvalData = (ApprovalDataVO) (approvalSession.query(internalAdmin, q, 0, 1, "cAId="+approvalCAID, "(endEntityProfileId="+SecConst.EMPTY_ENDENTITYPROFILE+")").get(0));
                            Approval approval = new Approval("Approved during testing.");
                            approvalSession.approve(approvingAdmin, approvalID, approval, raAdminSession.loadGlobalConfiguration(new Admin(Admin.INTERNALCAID)));
                            approvalData = (ApprovalDataVO) approvalSession.findApprovalDataVO(internalAdmin, approvalID).iterator().next();
                            assertEquals(approvalData.getStatus(), ApprovalDataVO.STATUS_EXECUTED);
                    CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serialNumber);
                            assertEquals(status.revocationReason, reason);
                            approvalSession.removeApprovalRequest(internalAdmin, approvalData.getId());
                    approvedRevocations++;
                }
        }
        return approvedRevocations;
    } // approveRevocation
}
