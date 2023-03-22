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

package org.ejbca.core.ejb.ca.store;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.certextensions.standard.QcStatement;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests certificate store.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CertReqHistorySessionTest {

    private static final Logger log = Logger.getLogger(CertReqHistorySessionTest.class);
    private static X509Certificate cert1;
    private static X509Certificate cert2;
    private static String username = "";
    private static KeyPair keyPair;

    private CertReqHistoryProxySessionRemote certReqHistoryProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertReqHistoryProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        CryptoProviderTools.installBCProvider();
        keyPair = KeyTools.genKeys("512", "RSA");
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Adds two certificate request history data to the database.
     * 
     */
    @Test
    public void test01addCertReqHist() throws Exception {
        log.trace(">test01addCertReqHist()");

        cert1 = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1", 24, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        cert2 = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2", 24, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);

        final EndEntityInformation userdata = new EndEntityInformation();
        userdata.setUsername("1111");
        userdata.setCAId(11111);
        userdata.setDN("CN=1111");
        userdata.setCertificateProfileId(1);
        userdata.setEndEntityProfileId(1);
        userdata.setSubjectAltName("rfc822Name=1@se");
        userdata.setTokenType(1);
        userdata.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        userdata.setTimeCreated(new Date());
        userdata.setTimeModified(new Date());
        final ExtendedInformation ei = new ExtendedInformation();
        ei.setAddEndEntityApprovalRequestId(123);
        ei.addEditEndEntityApprovalRequestId(123);
        ei.addEditEndEntityApprovalRequestId(456);
        final List<PSD2RoleOfPSPStatement> pspRoles = new ArrayList<>();
        pspRoles.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid("PSP_AS"), "PSP_AS"));
        pspRoles.add(new PSD2RoleOfPSPStatement(QcStatement.getPsd2Oid("PSP_PI"), "PSP_PI"));
        ei.setQCEtsiPSD2RolesOfPSP(pspRoles);
        ei.setQCEtsiPSD2NcaName("QCEtsiPSD2NcaName");
        ei.setQCEtsiPSD2NcaId("NcaId-123");
        ei.setCabfOrganizationIdentifier("cabf");
        ei.setCertificateRequest("foo123".getBytes());
        ei.cacheScepRequest("1234567890"); // should be base64 encoded message actually
        ei.cacheApprovalType(EditEndEntityApprovalRequest.class);
        ei.setExtensionData("extensiondata", "value");
        userdata.setExtendedInformation(ei);
        Random rand = new Random(new Date().getTime() + 4711);
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        userdata.setUsername(username);
        userdata.setDN("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1");
        certReqHistoryProxySession.addCertReqHistoryData(cert1, userdata);

        userdata.setDN("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2");
        certReqHistoryProxySession.addCertReqHistoryData(cert2, userdata);
        log.trace("<test01addCertReqHist()");
    }

    /**
     * checks that getCertReqHistory(Admin admin, BigInteger certificateSN,
     * String issuerDN) returns the right data.
     * Needs to be run after test01addCertReqHist as it reads the information stored by that test
     */
    @Test
    public void test02getCertReqHistByIssuerDNAndSerial() throws Exception {
        log.trace(">test10getCertReqHistByIssuerDNAndSerial()");

        CertReqHistory certreqhist = certReqHistoryProxySession.retrieveCertReqHistory(cert1.getSerialNumber(), cert1.getIssuerDN().toString());

        assertNotNull("Error couldn't find the certificate request data stored previously", certreqhist);

        EndEntityInformation userdata = certreqhist.getEndEntityInformation();
        assertTrue("Error wrong username.", (userdata.getUsername().equals(username)));
        assertTrue("Error wrong DN.", (userdata.getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1")));
        final ExtendedInformation ei = userdata.getExtendedInformation();
        assertEquals(Integer.valueOf(123), ei.getAddEndEntityApprovalRequestId());
        final List<Integer> list = ei.getEditEndEntityApprovalRequestIds();
        assertEquals(2, list.size());
        assertEquals(Integer.valueOf(123), list.get(0));
        assertEquals(Integer.valueOf(456), list.get(1));
        assertEquals("foo123", new String(ei.getCertificateRequest()));
        final List<PSD2RoleOfPSPStatement> psd2RoleOfPSPStatements = ei.getQCEtsiPSD2RolesOfPSP();
        assertEquals(2, psd2RoleOfPSPStatements.size());
        assertEquals("PSP_AS", psd2RoleOfPSPStatements.get(0).getName());
        assertEquals(QcStatement.getPsd2Oid("PSP_AS"), psd2RoleOfPSPStatements.get(0).getOid());
        assertEquals("PSP_PI", psd2RoleOfPSPStatements.get(1).getName());
        assertEquals(QcStatement.getPsd2Oid("PSP_PI"), psd2RoleOfPSPStatements.get(1).getOid());
        assertEquals("NcaId-123", ei.getQCEtsiPSD2NCAId());
        assertEquals("QCEtsiPSD2NcaName", ei.getQCEtsiPSD2NCAName());
        assertEquals("cabf", ei.getCabfOrganizationIdentifier());
        assertEquals("1234567890", ei.getCachedScepRequest());
        assertEquals("value", ei.getExtensionData("extensiondata"));
        assertEquals(EditEndEntityApprovalRequest.class.getName(), ei.getCachedApprovalType().getName());

        log.trace("<test10getCertReqHistByIssuerDNAndSerial()");
    }

    /**
     * checks that getCertReqHistory(Admin admin, String username) returns the
     * the two CertReqHistory object previously stored.
     * 
     */
    @Test
    public void test03getCertReqHistByUsername() throws Exception {
        log.trace(">test11getCertReqHistByUsername()");
        Collection<CertReqHistory> result = certReqHistoryProxySession.retrieveCertReqHistory(username);
        assertTrue("Error size of the returned collection.", (result.size() == 2));

        Iterator<CertReqHistory> iter = result.iterator();
        while (iter.hasNext()) {
            CertReqHistory certreqhist = iter.next();
            assertTrue("Error wrong DN", ((certreqhist.getEndEntityInformation().getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1")) || (certreqhist
                    .getEndEntityInformation().getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2"))));
        }
        log.trace("<test11getCertReqHistByUsername()");
    }

    /**
     * Removes all the previously stored certreqhist data.
     * 
     */
    @Test
    public void test04removeCertReqHistData() throws Exception {
        log.trace(">test12removeCertReqHistData()");

        certReqHistoryProxySession.removeCertReqHistoryData(CertTools.getFingerprintAsString(cert1));
        certReqHistoryProxySession.removeCertReqHistoryData(CertTools.getFingerprintAsString(cert2));

        CertReqHistory certreqhist = certReqHistoryProxySession.retrieveCertReqHistory(cert1.getSerialNumber(), cert1.getIssuerDN().toString());
        assertNull("Error removing cert req history data, cert1 data is still there", certreqhist);

        certreqhist = certReqHistoryProxySession.retrieveCertReqHistory(cert2.getSerialNumber(), cert2.getIssuerDN().toString());
        assertNull("Error removing cert req history data, cert2 data is still there", certreqhist);

        log.trace("<test12removeCertReqHistData()");
    }

}
