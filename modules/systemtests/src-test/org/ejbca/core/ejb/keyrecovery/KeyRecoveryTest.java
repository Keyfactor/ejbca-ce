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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the key recovery modules.
 * 
 * @version $Id$
 */
public class KeyRecoveryTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(KeyRecoveryTest.class);
    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    private static final String user = genRandomUserName();
    private static KeyPair keypair = null;
    private static X509Certificate cert = null;

    private KeyRecoverySessionRemote keyRecoverySession = InterfaceCache.getKeyRecoverySession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();

    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }
    
    /**
     * tests adding a keypair and checks if it can be read again.
     * 
     * @throws Exception error
     */
    @Test
    public void testAddAndRemoveKeyPair() throws Exception {
        log.trace(">test01AddKeyPair()");
        // Generate test keypair and certificate.
        try {
            try {
                String email = "test@test.se";
                if (!userAdminSession.existsUser(admin, user)) {
                    keypair = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                    userAdminSession.addUser(admin, user, "foo123", "CN=TESTKEYREC" + new Random().nextLong(), "rfc822name=" + email, email, false,
                            SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0,
                            getTestCAId());
                    cert = (X509Certificate) signSession.createCertificate(admin, user, "foo123", keypair.getPublic());
                }
            } catch (Exception e) {
                log.error("Exception generating keys/cert: ", e);
                fail("Exception generating keys/cert");
            }
            keyRecoverySession.addKeyRecoveryData(admin, cert, user, keypair);
            assertTrue("Couldn't save key's in database", keyRecoverySession.existsKeys(admin, cert));
            log.trace("<test01AddKeyPair()");
            log.trace(">test02MarkAndRecoverKeyPair()");
            assertFalse("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(admin, user));
            userAdminSession.prepareForKeyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(admin, user));
            KeyRecoveryData data = keyRecoverySession.keyRecovery(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);

            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));
            log.trace("<test02MarkAndRecoverKeyPair()");
        } finally {
            log.trace(">test03RemoveKeyPair()");
            keyRecoverySession.removeKeyRecoveryData(admin, cert);
            assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(admin, cert));
            log.trace("<test03RemoveKeyPair()");
        }
    }

}
