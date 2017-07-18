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

package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/** This is a performance test:
 * - 10 threads generates 1000 certificates each with 1024 bit public key
 * - CA uses 2048 bit signature key
 * - total time for certificate generation is counted to get number of certificates generated per second
 * 
 * @version $Id$
 */
public class SignLotsOfCertsTest extends CaTestCase {

    private static final String USERNAME_PREFIX = "SignLotsOfCertsTest";
    
	private static final Logger log = Logger.getLogger(SignLotsOfCertsTest.class);

    private static final String CANAME = "TESTPERF1";
    private int caid = getTestCAId(CANAME);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SignLotsOfCertsTest"));

    public static KeyPair keys;
     
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    /**
     * Creates a new TestSignSession object.
     *
     * @param name name
     */
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();	
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        log.trace(">setUp()");
        if (keys == null) {
            keys = KeyTools.genKeys("1024", "RSA");
        }
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        removeTestCA(CANAME);
        deleteUser("_no1");
        deleteUser("_no2");
        deleteUser("_no3");
        deleteUser("_no4");
        deleteUser("_no5");
        deleteUser("_no6");
        deleteUser("_no7");
        deleteUser("_no8");
        deleteUser("_no9");
        deleteUser("_no10");
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    private void newUser(String suffix) throws Exception {
        // Make user that we know...
        boolean userExists = false;
        final String username = USERNAME_PREFIX + suffix;
        final String subjectDn = "CN="+username;
        EndEntityInformation endEntityInformation = new EndEntityInformation(username, subjectDn, caid, null, null, EndEntityTypes.ENDUSER.toEndEntityType(), 
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        endEntityInformation.setPassword("foo123");
        try {
            endEntityManagementSession.addUser(admin, endEntityInformation, true);
            log.debug("created user: " + username + ", " + subjectDn);
        } catch (EndEntityExistsException e) {
            userExists = true;
        }
        if (userExists) {
            log.info("User performancefoo already exists, resetting status.");
            endEntityManagementSession.setUserStatus(admin, USERNAME_PREFIX + suffix, EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        //Verify that user exists
        if(endEntityAccessSession.findUser(admin, username) == null) {
            throw new IllegalStateException("User was not created, cannot continue.");
        }

    }

    private void deleteUser(String suffix) throws Exception {
        String username = USERNAME_PREFIX + suffix;
        try {
            endEntityManagementSession.deleteUser(admin, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
        } catch (NoSuchEndEntityException e) {
            //NOPMD: Ignore
        } 
    }

    @Test
    public void testSignLotsOfCerts() throws Exception {
        //roleManagementSession.init(admin, getTestCAId(CANAME), DEFAULT_SUPERADMIN_CN);
        if(!createTestCA(CANAME, 2048)) {
            fail("Could not create test CA, cannot continue");
        }
        CAInfo caInfo = caSession.getCAInfo(admin, CANAME);
        caInfo.setDoEnforceUniquePublicKeys(false);
        caSession.editCA(admin, caInfo);
        X509Certificate cert = (X509Certificate) caInfo.getCertificateChain().iterator().next();
        assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=" + CANAME));
        assertTrue("Creating CA failed", caInfo.getSubjectDN().equals("CN=" + CANAME));
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
        } else {
            fail("Public key is not an RSA key.");
        }
        assertTrue("CA is not valid for the specified duration.", cert.getNotAfter().after(new Date(new Date().getTime() + 10 * 364 * 24 * 60 * 60 * 1000L))
                && cert.getNotAfter().before(new Date(new Date().getTime() + 10 * 366 * 24 * 60 * 60 * 1000L)));

        newUser("_no1");
        newUser("_no2");
        newUser("_no3");
        newUser("_no4");
        newUser("_no5");
        newUser("_no6");
        newUser("_no7");
        newUser("_no8");
        newUser("_no9");
        newUser("_no10");

        long before = System.currentTimeMillis();
        Thread no1 = new Thread(new SignTester(), "_no1"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no2 = new Thread(new SignTester(), "_no2"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no3 = new Thread(new SignTester(), "_no3"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no4 = new Thread(new SignTester(), "_no4"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no5 = new Thread(new SignTester(), "_no5"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no6 = new Thread(new SignTester(), "_no6"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no7 = new Thread(new SignTester(), "_no7"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no8 = new Thread(new SignTester(), "_no8"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no9 = new Thread(new SignTester(), "_no9"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no10 = new Thread(new SignTester(), "_no10"); // NOPMD we want to use thread here, it's not a JEE app
        no1.start();
        log.info("Started no1");
        no2.start();
        log.info("Started no2");
        no3.start();
        log.info("Started no3");
        no4.start();
        log.info("Started no4");
        no5.start();
        log.info("Started no5");
        no6.start();
        log.info("Started no6");
        no7.start();
        log.info("Started no7");
        no8.start();
        log.info("Started no8");
        no9.start();
        log.info("Started no9");
        no10.start();
        log.info("Started no10");
        no1.join();
        no2.join();
        no3.join();
        no4.join();
        no5.join();
        no6.join();
        no7.join();
        no8.join();
        no9.join();
        no10.join();
        long after = System.currentTimeMillis();
        long diff = after - before;
        log.info("All threads finished. Total time: " + diff + " ms");
        int noOfGeneratedCerts = (10 * SignTester.NO_CERTS);
        log.info("Generated " + noOfGeneratedCerts + " certificates in total.");
        BigDecimal d = new BigDecimal(diff).divide(new BigDecimal(1000));
        BigDecimal noCerts = new BigDecimal(noOfGeneratedCerts).divide(d, 2, RoundingMode.UP);
        log.info("Performance is " + noCerts.intValue() + " certs/sec.");
    }

    private class SignTester implements Runnable { // NOPMD we want to use thread here, it's not a JEE app

        public static final int NO_CERTS = 1000;

        public void run() {
            try {
                String username = USERNAME_PREFIX + Thread.currentThread().getName();
                long before = System.currentTimeMillis();
                for (int i = 0; i < NO_CERTS; i++) {
                    endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
                    X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, username, "foo123", new PublicKeyWrapper(keys.getPublic()));
                    assertNotNull("Failed to create certificate", cert);
                    if ((i % 100) == 0) {
                        long mellantid = System.currentTimeMillis() - before;
                        log.info(Thread.currentThread().getName() + " has generated " + i + ", time=" + mellantid);
                    }
                }
                long after = System.currentTimeMillis();
                long diff = after - before;
                log.info("Time used (" + Thread.currentThread().getName() + "): " + diff);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
