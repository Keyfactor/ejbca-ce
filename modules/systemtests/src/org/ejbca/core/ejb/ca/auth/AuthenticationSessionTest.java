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

package org.ejbca.core.ejb.ca.auth;

import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.ejb.DuplicateKeyException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;


/**
 * Tests authentication session used by signer.
 *
 * @version $Id: TestAuthenticationSession.java 8061 2009-10-02 18:53:32Z jeklund $
 */
public class AuthenticationSessionTest extends TestCase {
    private static final Logger log = Logger.getLogger(AuthenticationSessionTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final int caid = TestTools.getTestCAId();

    private static final int MAXFAILEDLOGINS = 4;
    
    private static String username1;
    private static String pwd1;
    private static String username2;
    private static String pwd2;

    /**
     * Creates a new TestAuthenticationSession object.
     *
     * @param name name
     */
    public AuthenticationSessionTest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", TestTools.createTestCA());
    }

    protected void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

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

    private static void createUser(Admin admin, String username, String password, int caID, int endEntityProfileId, int certProfileId, int maxFailedLogins) throws DuplicateKeyException, RemoteException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException, Exception {
		log.info("createUser: username="+username+", certProfileId="+certProfileId);
		UserDataVO userdata = new UserDataVO(username, "CN="+username, caID, null, null, 1, endEntityProfileId, certProfileId, SecConst.TOKEN_SOFT_P12, 0, null);
		ExtendedInformation ei = new ExtendedInformation();
		ei.setMaxLoginAttempts(maxFailedLogins);
		ei.setRemainingLoginAttempts(maxFailedLogins);
		userdata.setExtendedinformation(ei);
		userdata.setPassword(password);
		TestTools.getUserAdminSession().addUser(admin, userdata, true);
	    UserDataVO userdata2 = TestTools.getUserAdminSession().findUser(admin, userdata.getUsername());
	    assertNotNull("findUser: " + userdata.getUsername(), userdata2);
	}

    /**
     * tests creation of new users
     *
     * @throws Exception error
     */
    public void test01CreateNewUser() throws Exception {
        log.trace(">test01CreateNewUser()");

        // Make user that we know later...
        username1 = TestTools.genRandomUserName();
        pwd1 = genRandomPwd();
        String email = username1 + "@anatom.se";
        TestTools.getUserAdminSession().addUser(admin, username1, pwd1, "C=SE, O=AnaTom, CN=" + username1, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        log.debug("created user: " + username1 + ", " + pwd1 + ", C=SE, O=AnaTom, CN=" + username1);
        
        // Make another user that we know later...
        username2 = TestTools.genRandomUserName();
        pwd2 = genRandomPwd();
        createUser(admin, username2, pwd2, caid, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, MAXFAILEDLOGINS);
        log.debug("created user: " + username2 + ", " + pwd2 + ", C=SE, O=AnaTom, CN=" + username2);

        log.trace("<test01CreateNewUser()");
    }

    /**
     * Tests authentiction of users
     *
     * @throws Exception error
     */
    public void test02AuthenticateUser() throws Exception {
        log.trace(">test02AuthenticateUser()");
        // user that we know exists...
        log.debug("Username:" + username1 + "\npwd:" + pwd1);
        UserDataVO data = TestTools.getAuthenticationSession().authenticateUser(admin, username1, pwd1);

        log.debug("DN: " + data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf(username1) != -1);

        log.debug("Email: " + data.getEmail());
        assertNotNull("Email should not be null", data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals(username1 + "@anatom.se"));

        log.debug("Type: " + data.getType());
        assertTrue("Type is wrong", data.getType() == SecConst.USER_ENDUSER);
        log.trace("<test02AuthenticateUser()");
    }

    /**
     * Tests filed authentication
     *
     * @throws Exception error
     */
    public void test03FailAuthenticateUser() throws Exception {
        log.trace(">test03FailAuthenticateUser()");
        // Set status to GENERATED so authentication will fail
        TestTools.getUserAdminSession().setUserStatus(admin,username1,UserDataConstants.STATUS_GENERATED);
        boolean authfailed = false;
        try {
            UserDataVO auth = TestTools.getAuthenticationSession().authenticateUser(admin, username1, pwd1);
            log.debug("Authenticated user: "+auth.getUsername());
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.trace("<test03FailAuthenticateUser()");
    }

    /**
     * Tests more failed authentication
     *
     * @throws Exception error
     */
    public void test04FailAuthenticateUser() throws Exception {
        log.trace(">test04FailAuthenticateUser()");
        // user that we know exists... but we issue wrong password
        boolean authfailed = false;
        try {
            UserDataVO auth = TestTools.getAuthenticationSession().authenticateUser(admin, username1, "abc123");
            log.debug("Authenticated user: "+auth.getUsername());
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.trace("<test04FailAuthenticateUser()");
    }

    /**
     * Test reset of key recovery mark.
     * 
     * @throws Exception
     */
    public void test05UnmarkKeyRecoveryOnFinish() throws Exception {
    	log.trace(">test05UnmarkKeyRecoveryOnFinish()");
    	
    	GlobalConfiguration config = TestTools.getRaAdminSession().loadGlobalConfiguration(admin);
    	boolean orgkeyrecconfig = config.getEnableKeyRecovery();
    	config.setEnableKeyRecovery(true);
    	TestTools.getRaAdminSession().saveGlobalConfiguration(admin,config);
    	
        // create certificate for user
        //    	 Set status to NEW        
        TestTools.getUserAdminSession().setPassword(admin, username1, "foo123");
        TestTools.getUserAdminSession().setUserStatus(admin, username1, UserDataConstants.STATUS_NEW);
        
    	// Create a dummy certificate and keypair.
    	KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
    	X509Certificate cert = (X509Certificate) TestTools.getSignSession().createCertificate(admin,username1,"foo123",keys.getPublic()); 
    	
    	// First mark the user for recovery
    	TestTools.getKeyRecoverySession().addKeyRecoveryData(admin, cert, username1, keys);
    	TestTools.getUserAdminSession().prepareForKeyRecovery(admin, username1, SecConst.EMPTY_ENDENTITYPROFILE, null);
    	
		assertTrue("Failure the users keyrecovery session should have been marked", TestTools.getKeyRecoverySession().isUserMarked(admin,username1));
		
    	// Now finish the user (The actual test)
		TestTools.getAuthenticationSession().finishUser(admin,username1,pwd1);
		// And se if the user is still marked
		
		assertTrue("Failure the users keyrecovery session should have been unmarked", !TestTools.getKeyRecoverySession().isUserMarked(admin,username1));
		
		// Clean up
		TestTools.getKeyRecoverySession().removeAllKeyRecoveryData(admin,username1);
		
		config.setEnableKeyRecovery(orgkeyrecconfig);
    	TestTools.getRaAdminSession().saveGlobalConfiguration(admin,config);
    	log.trace("<test05UnmarkKeyRecoveryOnFinish()");
    }
    
    /**
     * Tests that (maxNumFailedLogins-1) tries can be done and then after a correct login the remainingLoginAttempts is reset so
     * that (maxNumFailedLogins) can be performed before the account is locked which is then tested by trying to login using 
     * the correct password.
     */
    public void test06MultipleFailedLogins() throws Exception {
    	log.trace(">test06FailedLoginsThenCorrect()");
    	
    	assertEquals(MAXFAILEDLOGINS, 4);
    	
    	// Test that we don't lock the account to early
    	loginMaxNumFailedLoginsMinusOneAndThenOk(username2, pwd2);
    	
    	// Test that we lock the account
        loginUntilLocked(username2, pwd2);
        
        // Reset the status
        TestTools.getUserAdminSession().setUserStatus(admin, username2, UserDataConstants.STATUS_NEW);
        
        // After reset: Test that we don't lock the account to early
    	loginMaxNumFailedLoginsMinusOneAndThenOk(username2, pwd2);
        
    	// After reset: Test that we lock the account
        loginUntilLocked(username2, pwd2);
        
    	log.trace("<test06FailedLoginsThenCorrect()");
    }
    
    private void loginMaxNumFailedLoginsMinusOneAndThenOk(String username, String password) throws Exception {
    	// Login attempt: 1
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 2
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 3
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 4: This time with the right password which should work
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, password);
        } catch (AuthStatusException e) { // This time the status is wrong
        	fail("The account shold not have been locked");
        } catch (AuthLoginException e) {
        	fail("Authentication should have succeeded");
        }
    }
    
    private void loginUntilLocked(String username, String password) throws Exception {
    	// Login attempt: 1
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 2
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 3
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 4
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
        	// OK
        }
        // Login attempt: 5: This time with the right password but the account should have been locked
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, password);
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthStatusException e) { // This time the status is wrong
        	// OK
        }
        
        // Login attempt: 6: Should still be locked
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, password);
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthStatusException e) { // This time the status is wrong
        	// OK
        }
        
        // Login attempt: 7: Should still be locked
        try {
            TestTools.getAuthenticationSession().authenticateUser(admin, username, password);
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthStatusException e) { // This time the status is wrong
        	// OK
        }
    }
    
    /**
     * Delete user after completed tests
     *
     * @throws Exception error
     */
    public void test98DeleteUsers() throws Exception {
        log.trace(">test98DeleteUsers()");
        
        TestTools.getUserAdminSession().deleteUser(admin, username1);
        log.debug("deleted user: " + username1);
        
        TestTools.getUserAdminSession().deleteUser(admin, username2);
        log.debug("deleted user: " + username2);
        
        log.trace("<test98eleteUsers()");
    }

	public void test99RemoveTestCA() throws Exception {
		TestTools.removeTestCA();
	}
}
