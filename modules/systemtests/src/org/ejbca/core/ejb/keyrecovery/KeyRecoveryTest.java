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
import java.util.Random;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

/**
 * Tests the key recovery modules.
 *
 * @version $Id$
 */
public class KeyRecoveryTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(KeyRecoveryTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final String user = genRandomUserName();
    private static KeyPair keypair = null;
    private static X509Certificate cert = null;

    private KeyRecoverySessionRemote keyRecoverySession = InterfaceCache.getKeyRecoverySession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    
    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public KeyRecoveryTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
        
    }

    public void setUp() throws Exception {
        super.setUp();
        log.trace(">setUp()");
        assertTrue("Could not create TestCA.", createTestCA());
        log.trace("<setUp()");
    }

    public void tearDown() throws Exception {
        super.tearDown();
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
            if (!userAdminSession.existsUser(admin, user)) {
                keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                userAdminSession.addUser(admin, user, "foo123", "CN=TESTKEYREC" + new Random().nextLong(), "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, getTestCAId());
                cert = (X509Certificate) signSession.createCertificate(admin, user, "foo123", keypair.getPublic());
            }
        } catch (Exception e) {
            log.error("Exception generating keys/cert: ", e);
            assertTrue("Exception generating keys/cert", false);            
        }
        keyRecoverySession.addKeyRecoveryData(admin, cert, user, keypair);
        assertTrue("Couldn't save key's in database", keyRecoverySession.existsKeys(admin, cert));
        log.trace("<test01AddKeyPair()");
    }

    /**
     * tests marks the keypair in database and recovers it.
     *
     * @throws Exception error
     */
    public void test02MarkAndRecoverKeyPair() throws Exception {
        log.error("User:::: " + user);
        log.trace(">test02MarkAndRecoverKeyPair()");
        CryptoProviderTools.installBCProvider();
        assertFalse("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(admin, user));
        userAdminSession.prepareForKeyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert);
        assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(admin, user));
        KeyRecoveryData data = keyRecoverySession.keyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);

        assertTrue("Couldn't recover keys from database", Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));

        log.trace("<test02MarkAndRecoverKeyPair()");
    }

    /**
     * tests removes all keydata.
     *
     * @throws Exception error
     */
    public void test03RemoveKeyPair() throws Exception {
        log.error("User:::: " + user);
        log.trace(">test03RemoveKeyPair()");
        CryptoProviderTools.installBCProvider();
        keyRecoverySession.removeKeyRecoveryData(admin, cert);
        assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(admin, cert));

        log.trace("<test03RemoveKeyPair()");
    }

	public void test99RemoveTestCA() throws Exception {
		removeTestCA();
	}
}
