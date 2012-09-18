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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalTest;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.Query;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * These tests test RA functionality with the CMP protocol, i.e. a "trusted" RA sends CMP messages authenticated using PBE (password based encryption)
 * and these requests are handled by EJBCA without further authentication, end entities are created automatically in EJBCA.
 * 
 * 'ant clean; ant bootstrap' to deploy configuration changes.
 * 
 * @author tomas
 * @version $Id: CrmfRAPbeRequestTest.java 9435 2010-07-14 15:18:39Z mikekushner$
 */
public class CrmfRAPbeRequestTest extends CmpTestCase {

    private static final Logger log = Logger.getLogger(CrmfRAPbeRequestTest.class);

    private static final String PBEPASSWORD = "password";

    private static final String CPNAME = CrmfRAPbeRequestTest.class.getName();
    private static final String EEPNAME = CrmfRAPbeRequestTest.class.getName();

    /**
     * userDN of user used in this test, this contains special, escaped, characters to test that this works with CMP RA operations
     */
    private static String userDN = "C=SE,O=PrimeKey'foo'&bar\\,ha\\<ff\\\"aa,CN=cmptest";

    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;

    private static int caid = 0;
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrmfRAPbeRequestTest"));
    private static X509Certificate cacert = null;

    private final String cliUserName = EjbcaConfiguration.getCliDefaultUser();
    private final String cliPassword = EjbcaConfiguration.getCliDefaultPassword();
    
    private ApprovalExecutionSessionRemote approvalExecutionSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalExecutionSessionRemote.class);
    private ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private GlobalConfigurationSessionRemote raAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
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
        updatePropertyOnServer(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "pbe");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, PBEPASSWORD);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, CPNAME);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, EEPNAME);
        updatePropertyOnServer(CmpConfiguration.CONFIG_RACANAME, cainfo.getName());
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONMODULE, CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC);
        updatePropertyOnServer(CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS, "-;-");
        // Configure a Certificate profile (CmpRA) using ENDUSER as template and
        // check "Allow validity override".
        if (certificateProfileSession.getCertificateProfile(CPNAME) == null) {
            CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp.setAllowValidityOverride(true);
            try { // TODO: Fix this better
                certificateProfileSession.addCertificateProfile(admin, CPNAME, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
            }
        }
        int cpId = certificateProfileSession.getCertificateProfileId(CPNAME);
        if (endEntityProfileSession.getEndEntityProfile(EEPNAME) == null) {
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
                endEntityProfileSession.addEndEntityProfile(admin, EEPNAME, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
        }

        if (keys == null) {
            keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        }

    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        
        endEntityProfileSession.removeEndEntityProfile(admin, EEPNAME);
        certificateProfileSession.removeCertificateProfile(admin, CPNAME);
        if (!configurationSession.restoreConfiguration()) {
            throw new RuntimeException("Unable to restore configuration");
        }
    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void test01CrmfHttpOkUser() throws Exception {
        try {
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
            PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, notBefore, notAfter, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);
            assertNotNull(req);

            int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD);
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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD);
            checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, true);
            int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);

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
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD);
            checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, false);
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, "cmptest");
            } catch (NotFoundException e) {
                // NOPMD: ignore
            }
        }
    }

    /** Tests the cmp configuration settings:
     * cmp.ra.certificateprofile=KeyId
     * cmp.ra.certificateprofile=ProfileDefault
     * 
     * KeyId means that the certificate profile used to issue the certificate is the same as the KeyId sent in the request.
     * ProfileDefault means that the certificate profile used is taken from the default certificate profile in the end entity profile.
     */
    @Test
    public void test02KeyIdProfiles() throws Exception {
        final String keyId = "CmpTestKeyIdProfileName";
        final String keyIdDefault = "CmpTestKeyIdProfileNameDefault";
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "KeyId");
        updatePropertyOnServer(CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, "KeyId");
        try {
            final byte[] nonce = CmpMessageHelper.createSenderNonce();
            final byte[] transid = CmpMessageHelper.createSenderNonce();

            // Create one EE profile and 2 certificate profiles, one of the certificate profiles
            // (that does not have the same name as KeyId) will be the default in the EE profile.
            // First we will use "KeyId" for both profiles, and then we will use ProfileDefault for the cert profile
            CertificateProfile cp1 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp1.setUseSubjectAlternativeName(true);
            // Add a weird CDP, so we are sure this is the profile used
            final String cdp1 = "http://keyidtest/crl.crl";
            cp1.setCRLDistributionPointURI(cdp1);
            cp1.setUseCRLDistributionPoint(true);
            CertificateProfile cp2 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            cp2.setUseSubjectAlternativeName(false);
            final String cdp2 = "http://keyidtestDefault/crl.crl";
            cp2.setCRLDistributionPointURI(cdp2);
            cp2.setUseCRLDistributionPoint(true);
            try {
                certificateProfileSession.addCertificateProfile(admin, keyId, cp1);
            } catch (CertificateProfileExistsException e) {
                log.error("Error adding certificate profile: ", e);
            }
            try {
                certificateProfileSession.addCertificateProfile(admin, keyIdDefault, cp2);
            } catch (CertificateProfileExistsException e) {
                log.error("Error adding certificate profile: ", e);
            }

            int cpId1 = certificateProfileSession.getCertificateProfileId(keyId);
            int cpId2 = certificateProfileSession.getCertificateProfileId(keyIdDefault);
            // Configure an EndEntity profile with allow CN, O, C in DN
            // and rfc822Name (uncheck 'Use entity e-mail field' and check
            // 'Modifyable'), MS UPN in altNames in the end entity profile.
            EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + cpId2);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId1+";"+cpId2);
            eep.setModifyable(DnComponents.RFC822NAME, 0, true);
            eep.setUse(DnComponents.RFC822NAME, 0, false); // Don't use field
            // from "email" data
            try {
                endEntityProfileSession.addEndEntityProfile(admin, keyId, eep);
            } catch (EndEntityProfileExistsException e) {
                log.error("Could not create end entity profile.", e);
            }
            
            // In this test userDN contains special, escaped characters to verify
            // that that works with CMP RA as well
            PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
            PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, keyId, 567);
            assertNotNull(req);

            int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            DEROutputStream out = new DEROutputStream(bao);
            out.writeObject(req);
            byte[] ba = bao.toByteArray();
            // Send request and receive response
            byte[] resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD);
            X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            String altNames = CertTools.getSubjectAlternativeName(cert);
            assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
            assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);
            final URL cdpfromcert1 = CertTools.getCrlDistributionPoint(cert);
            assertEquals("CDP is not correct, it probably means it was not the correct 'KeyId' certificate profile that was used", cdp1, cdpfromcert1.toString());
            
            // Update property on server so that we use ProfileDefault as certificate profile, should give a little different result
            updatePropertyOnServer(CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE, "ProfileDefault");
            
            // Make new request, the certificate should now be produced with the other certificate profile
            PKIMessage two = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
            PKIMessage req2 = protectPKIMessage(two, false, PBEPASSWORD, keyId, 567);
            assertNotNull(req2);

            reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
            bao = new ByteArrayOutputStream();
            out = new DEROutputStream(bao);
            out.writeObject(req);
            ba = bao.toByteArray();
            // Send request and receive response
            resp = sendCmpHttp(ba, 200);
            checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, PBEPASSWORD);
            cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
            altNames = CertTools.getSubjectAlternativeName(cert);
            assertNull(altNames);
            final URL cdpfromcert2 = CertTools.getCrlDistributionPoint(cert);
            assertEquals("CDP is not correct, it probably means it was not the correct 'KeyId' certificate profile that was used", cdp2, cdpfromcert2.toString());            
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, "cmptest");
            } catch (NotFoundException e) {
                // NOPMD: ignore
            }
            endEntityProfileSession.removeEndEntityProfile(admin, keyId);
            certificateProfileSession.removeCertificateProfile(admin, keyId);
            certificateProfileSession.removeCertificateProfile(admin, keyIdDefault);
        }
    }

    @Test
    public void test03CrmfHttpTooManyIterations() throws Exception {

        byte[] nonce = CmpMessageHelper.createSenderNonce();
        byte[] transid = CmpMessageHelper.createSenderNonce();

        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null, null);
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
        // expect a FailInfo.BAD_MESSAGE_CHECK
    }

    @Test
    public void test04RevocationApprovals() throws Exception {
        // Generate random username and CA name
        String randomPostfix = Integer.toString((new Random(new Date().getTime() + 4711)).nextInt(999999));
        String caname = "cmpRevocationCA" + randomPostfix;
        String username = "cmpRevocationUser" + randomPostfix;
        X509CAInfo cainfo = null;
        try {
            // Generate CA with approvals for revocation enabled
            int caID = RevocationApprovalTest.createApprovalCA(admin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession, caSession);
            // Get CA cert
            cainfo = (X509CAInfo) caSession.getCAInfo(admin, caID);
            assertNotNull(cainfo);
            X509Certificate newCACert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
            // Create a user and generate the cert
            EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, cainfo.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
            userdata.setPassword("foo123");
            endEntityManagementSession.addUser(admin, userdata, true);
            BatchMakeP12 makep12 = new BatchMakeP12();
            File tmpfile = File.createTempFile("ejbca", "p12");
            makep12.setMainStoreDir(tmpfile.getParent());
            makep12.createAllNew(cliUserName, cliPassword);
            Collection<java.security.cert.Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
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
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, PBEPASSWORD);
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
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, PBEPASSWORD);
            checkCmpFailMessage(resp, "The request is already awaiting approval.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0,
                    ResponseStatus.FAILURE.getValue());
            reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
            assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
            // Approve revocation and verify success

            approveRevocation(admin, admin, username, RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION,
                    ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession, approvalExecutionSession,
                    cainfo.getCAId());
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
            checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, PBEPASSWORD);
            checkCmpFailMessage(resp, "Already revoked.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0, ResponseStatus.FAILURE.getValue());
        } finally {
            // Delete user
            endEntityManagementSession.deleteUser(admin, username);
            // Nuke CA
            try {
                caAdminSession.revokeCA(admin, cainfo.getCAId(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
            } finally {
                caSession.removeCA(admin, cainfo.getCAId());
            }
        }
    } // test04RevocationApprovals

    /**
     * Find all certificates for a user and approve any outstanding revocation.
     */
    public int approveRevocation(AuthenticationToken internalAdmin, AuthenticationToken approvingAdmin, String username, int reason,
            int approvalType, CertificateStoreSessionRemote certificateStoreSession, ApprovalSessionRemote approvalSession,
            ApprovalExecutionSessionRemote approvalExecutionSession, int approvalCAID) throws Exception {
        Collection<java.security.cert.Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(username);
        Iterator<java.security.cert.Certificate> i = userCerts.iterator();
        int approvedRevocations = 0;
        while (i.hasNext()) {
            X509Certificate cert = (X509Certificate) i.next();
            String issuerDN = cert.getIssuerDN().toString();
            BigInteger serialNumber = cert.getSerialNumber();
            boolean isRevoked = certificateStoreSession.isRevoked(issuerDN, serialNumber);
            if ((reason != RevokedCertInfo.NOT_REVOKED && !isRevoked) || (reason == RevokedCertInfo.NOT_REVOKED && isRevoked)) {
                int approvalID;
                if (approvalType == ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE) {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, serialNumber, issuerDN);
                } else {
                    approvalID = RevocationApprovalRequest.generateApprovalId(approvalType, username, reason, null, null);
                }
                Query q = new Query(Query.TYPE_APPROVALQUERY);
                q.add(ApprovalMatch.MATCH_WITH_APPROVALID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(approvalID));
                ApprovalDataVO approvalData = (ApprovalDataVO) (approvalSession.query(internalAdmin, q, 0, 1, "cAId=" + approvalCAID,
                        "(endEntityProfileId=" + SecConst.EMPTY_ENDENTITYPROFILE + ")").get(0));
                Approval approval = new Approval("Approved during testing.");
                approvalExecutionSession.approve(approvingAdmin, approvalID, approval, raAdminSession.getCachedGlobalConfiguration());
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
