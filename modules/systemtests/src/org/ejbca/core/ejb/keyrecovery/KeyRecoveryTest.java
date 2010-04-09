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

package org.ejbca.core.ejb.keyrecovery;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Tests the key recovery modules.
 *
 * @version $Id$
 */
public class KeyRecoveryTest extends TestCase {
    private final static Logger log = Logger.getLogger(KeyRecoveryTest.class);
    private final static Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final String user = genRandomUserName();

    private static KeyPair keypair = null;
    private static X509Certificate cert = null;

    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public KeyRecoveryTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
    }

    protected void setUp() throws Exception {
        log.trace(">setUp()");
        assertTrue("Could not create TestCA.", TestTools.createTestCA());
        log.trace("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    /**
     * tests adding a keypair and checks if it can be read again.
     *
     * @throws Exception error
     */
    public void test01AddKeyPair() throws Exception {
        log.trace(">test01AddKeyPair()");
        // Generate test keypair and certificate.
        try {
            String email = "test@test.se";
            if (!TestTools.getUserAdminSession().existsUser(admin, user)) {
                keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                TestTools.getUserAdminSession().addUser(admin, user, "foo123", "CN=TESTKEYREC" + new Random().nextLong(), "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, TestTools.getTestCAId());
                cert = (X509Certificate) TestTools.getSignSession().createCertificate(admin, user, "foo123", keypair.getPublic());
            }
        } catch (Exception e) {
            log.error("Exception generating keys/cert: ", e);
            assertTrue("Exception generating keys/cert", false);            
        }
        TestTools.getKeyRecoverySession().addKeyRecoveryData(admin, cert, user, keypair);
        assertTrue("Couldn't save key's in database", TestTools.getKeyRecoverySession().existsKeys(admin, cert));
        log.trace("<test01AddKeyPair()");
    }

    /**
     * tests marks the keypair in database and recovers it.
     *
     * @throws Exception error
     */
    public void test02MarkAndRecoverKeyPair() throws Exception {
        log.trace(">test02MarkAndRecoverKeyPair()");
        CryptoProviderTools.installBCProvider();
        assertTrue("Couldn't mark user for recovery in database", !TestTools.getKeyRecoverySession().isUserMarked(admin, user));
        TestTools.getUserAdminSession().prepareForKeyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert);
        assertTrue("Couldn't mark user for recovery in database", TestTools.getKeyRecoverySession().isUserMarked(admin, user));
        KeyRecoveryData data = TestTools.getKeyRecoverySession().keyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);

        assertTrue("Couldn't recover keys from database", Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));

        log.trace("<test02MarkAndRecoverKeyPair()");
    }

    /**
     * tests removes all keydata.
     *
     * @throws Exception error
     */
    public void test03RemoveKeyPair() throws Exception {
        log.trace(">test03RemoveKeyPair()");
        CryptoProviderTools.installBCProvider();
        TestTools.getKeyRecoverySession().removeKeyRecoveryData(admin, cert);
        assertTrue("Couldn't remove keys from database", !TestTools.getKeyRecoverySession().existsKeys(admin, cert));

        log.trace("<test03RemoveKeyPair()");
    }

    private static String genRandomUserName() {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        //log.debug("Generated random username: username =" + username);
        return username;
    } // genRandomUserName

	public void test99RemoveTestCA() throws Exception {
		TestTools.removeTestCA();
	}
}
