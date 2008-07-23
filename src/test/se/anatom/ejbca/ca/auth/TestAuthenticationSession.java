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

package se.anatom.ejbca.ca.auth;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.CertTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;


/**
 * Tests authentication session used by signer.
 *
 * @version $Id$
 */
public class TestAuthenticationSession extends TestCase {
    private static final Logger log = Logger.getLogger(TestAuthenticationSession.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final int caid = TestTools.getTestCAId();

    private static String username;
    private static String pwd;

    /**
     * Creates a new TestAuthenticationSession object.
     *
     * @param name name
     */
    public TestAuthenticationSession(String name) {
        super(name);
        assertTrue("Could not create TestCA.", TestTools.createTestCA());
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        CertTools.installBCProvider();
        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String name = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            name += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        return name;
    } // genRandomUserName

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd


    /**
     * tests creation of new users
     *
     * @throws Exception error
     */
    public void test01CreateNewUser() throws Exception {
        log.debug(">test01CreateNewUser()");

        // Make user that we know later...
        username = genRandomUserName();
        pwd = genRandomPwd();
        String email = username + "@anatom.se";
        TestTools.getUserAdminSession().addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" + username);

        log.debug("<test01CreateNewUser()");
    }

    /**
     * Tests authentiction of users
     *
     * @throws Exception error
     */
    public void test02AuthenticateUser() throws Exception {
        log.debug(">test02AuthenticateUser()");
        // user that we know exists...
        log.debug("Username:" + username + "\npwd:" + pwd);
        UserDataVO data = TestTools.getAuthenticationSession().authenticateUser(admin, username, pwd);

        log.debug("DN: " + data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf(username) != -1);

        log.debug("Email: " + data.getEmail());
        assertNotNull("Email should not be null", data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals(username + "@anatom.se"));

        log.debug("Type: " + data.getType());
        assertTrue("Type is wrong", data.getType() == SecConst.USER_ENDUSER);
        log.debug("<test02AuthenticateUser()");
    }

    /**
     * Tests filed authentication
     *
     * @throws Exception error
     */
    public void test03FailAuthenticateUser() throws Exception {
        log.debug(">test03FailAuthenticateUser()");
        // Set status to GENERATED so authentication will fail
        TestTools.getUserAdminSession().setUserStatus(admin,username,UserDataConstants.STATUS_GENERATED);
        boolean authfailed = false;
        try {
            UserDataVO auth = TestTools.getAuthenticationSession().authenticateUser(admin, username, pwd);
            log.debug("Authenticated user: "+auth.getUsername());
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.debug("<test03FailAuthenticateUser()");
    }

    /**
     * Tests more failed authentication
     *
     * @throws Exception error
     */
    public void test04FailAuthenticateUser() throws Exception {
        log.debug(">test04FailAuthenticateUser()");
        // user that we know exists... but we issue wrong password
        boolean authfailed = false;
        try {
            UserDataVO auth = TestTools.getAuthenticationSession().authenticateUser(admin, username, "abc123");
            log.debug("Authenticated user: "+auth.getUsername());
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.debug("<test04FailAuthenticateUser()");
    }

    /**
     * Test reset of key recovery mark.
     * 
     * @throws Exception
     */
    public void test05UnmarkKeyRecoveryOnFinish() throws Exception {
    	log.debug(">test05UnmarkKeyRecoveryOnFinish()");
    	
    	GlobalConfiguration config = TestTools.getRaAdminSession().loadGlobalConfiguration(admin);
    	boolean orgkeyrecconfig = config.getEnableKeyRecovery();
    	config.setEnableKeyRecovery(true);
    	TestTools.getRaAdminSession().saveGlobalConfiguration(admin,config);
    	
        // create certificate for user
        //    	 Set status to NEW        
        TestTools.getUserAdminSession().setPassword(admin, username, "foo123");
        TestTools.getUserAdminSession().setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
        
    	// Create a dummy certificate and keypair.
    	KeyPair keys = KeyTools.genKeys("1024", CATokenConstants.KEYALGORITHM_RSA);
    	X509Certificate cert = (X509Certificate) TestTools.getSignSession().createCertificate(admin,username,"foo123",keys.getPublic()); 
    	
    	// First mark the user for recovery
    	TestTools.getKeyRecoverySession().addKeyRecoveryData(admin, cert, username, keys);
		TestTools.getKeyRecoverySession().markNewestAsRecoverable(admin,username,SecConst.EMPTY_ENDENTITYPROFILE);
    	
		assertTrue("Failure the users keyrecovery session should have been marked", TestTools.getKeyRecoverySession().isUserMarked(admin,username));
		
    	// Now finish the user (The actual test)
		TestTools.getAuthenticationSession().finishUser(admin,username,pwd);
		// And se if the user is still marked
		
		assertTrue("Failure the users keyrecovery session should have been unmarked", !TestTools.getKeyRecoverySession().isUserMarked(admin,username));
		
		// Clean up
		TestTools.getKeyRecoverySession().removeAllKeyRecoveryData(admin,username);
		
		config.setEnableKeyRecovery(orgkeyrecconfig);
    	TestTools.getRaAdminSession().saveGlobalConfiguration(admin,config);
    	log.debug("<test05UnmarkKeyRecoveryOnFinish()");
    }
    
    /**
     * Delete user after completed tests
     *
     * @throws Exception error
     */
    public void test06DeleteUser() throws Exception {
        log.debug(">test06DeleteUser()");
        TestTools.getUserAdminSession().deleteUser(admin, username);
        log.debug("deleted user: " + username);
        log.debug("<test06eleteUser()");
    }

	public void test99RemoveTestCA() throws Exception {
		TestTools.removeTestCA();
	}
}
