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

package org.ejbca.core.ejb.ca.store;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests certificate store.
 *
 * @version $Id$
 */
public class CertReqHistorySessionTest {

    private static final Logger log = Logger.getLogger(CertReqHistorySessionTest.class);
    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private static X509Certificate cert1;
    private static X509Certificate cert2;
    private static String username = "";
    private static KeyPair keyPair;

    private CertReqHistorySessionRemote certReqHistorySession = InterfaceCache.getCertReqHistorySession();

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
        log.trace(">test09addCertReqHist()");

        cert1 = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1", 24, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        cert2 = CertTools.genSelfCert("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2", 24, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);

        EndEntityInformation userdata = new EndEntityInformation();
        Random rand = new Random(new Date().getTime() + 4711);
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (Integer.valueOf(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        userdata.setUsername(username);
        userdata.setDN("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1");
        certReqHistorySession.addCertReqHistoryData(admin, cert1, userdata);

        userdata.setDN("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2");
        certReqHistorySession.addCertReqHistoryData(admin, cert2, userdata);
        log.trace("<test09addCertReqHist()");
    }

    /**
     * checks that getCertReqHistory(Admin admin, BigInteger certificateSN,
     * String issuerDN) returns the right data.
     * 
     */
    @Test
    public void test02getCertReqHistByIssuerDNAndSerial() throws Exception {
        log.trace(">test10getCertReqHistByIssuerDNAndSerial()");

        CertReqHistory certreqhist = certReqHistorySession.retrieveCertReqHistory(admin, cert1.getSerialNumber(), cert1.getIssuerDN().toString());

        assertNotNull("Error couldn't find the certificate request data stored previously", certreqhist);

        EndEntityInformation userdata = certreqhist.getUserDataVO();
        assertTrue("Error wrong username.", (userdata.getUsername().equals(username)));
        assertTrue("Error wrong DN.", (userdata.getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1")));

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
        Collection<CertReqHistory> result = certReqHistorySession.retrieveCertReqHistory(admin, username);
        assertTrue("Error size of the returned collection.", (result.size() == 2));

        Iterator<CertReqHistory> iter = result.iterator();
        while (iter.hasNext()) {
            CertReqHistory certreqhist = iter.next();
            assertTrue("Error wrong DN", ((certreqhist.getUserDataVO().getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist1")) || (certreqhist
                    .getUserDataVO().getDN().equals("C=SE,O=PrimeCA,OU=TestCertificateData,CN=CertReqHist2"))));
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

        certReqHistorySession.removeCertReqHistoryData(admin, CertTools.getFingerprintAsString(cert1));
        certReqHistorySession.removeCertReqHistoryData(admin, CertTools.getFingerprintAsString(cert2));

        CertReqHistory certreqhist = certReqHistorySession.retrieveCertReqHistory(admin, cert1.getSerialNumber(), cert1.getIssuerDN().toString());
        assertNull("Error removing cert req history data, cert1 data is still there", certreqhist);

        certreqhist = certReqHistorySession.retrieveCertReqHistory(admin, cert2.getSerialNumber(), cert2.getIssuerDN().toString());
        assertNull("Error removing cert req history data, cert2 data is still there", certreqhist);

        log.trace("<test12removeCertReqHistData()");
    }

}
