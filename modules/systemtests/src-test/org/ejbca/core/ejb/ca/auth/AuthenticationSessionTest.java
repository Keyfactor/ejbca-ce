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

package org.ejbca.core.ejb.ca.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.util.KeyPairWrapper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests authentication session used by signer.
 *
 * @version $Id$
 */
public class AuthenticationSessionTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(AuthenticationSessionTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AuthenticationSessionTest"));
    private int caid = getTestCAId();

    private static final int MAXFAILEDLOGINS = 4;

    private static String username1;
    private static String pwd1;
    private static String username2;
    private static String pwd2;

    private EndEntityAuthenticationSessionRemote authenticationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAuthenticationSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    /** Creates a new TestAuthenticationSession object. */
    @BeforeClass
    public static void beforeClass() throws Exception{
        CryptoProviderTools.installBCProvider();
        createTestCA();
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        removeTestCA();
    }

    @Before
    public void setUp() throws Exception {
        createNewUser();
    }

    @After
    public void tearDown() throws Exception {
        if (endEntityManagementSession.existsUser(username1)) {
            endEntityManagementSession.deleteUser(internalAdmin, username1);
        }
        if (endEntityManagementSession.existsUser(username2)) {
            endEntityManagementSession.deleteUser(internalAdmin, username2);
        }
    }

    private void createUser(AuthenticationToken admin, String username, String password, int caID, int endEntityProfileId, int certProfileId, int maxFailedLogins)
            throws EndEntityExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, ApprovalException,
            WaitingForApprovalException, Exception {
        log.info("createUser: username=" + username + ", certProfileId=" + certProfileId);
        EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caID, null, null, new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId, certProfileId, SecConst.TOKEN_SOFT_P12, 0,
                null);
        ExtendedInformation ei = new ExtendedInformation();
        ei.setMaxLoginAttempts(maxFailedLogins);
        ei.setRemainingLoginAttempts(maxFailedLogins);
        userdata.setExtendedinformation(ei);
        userdata.setPassword(password);
        endEntityManagementSession.addUser(admin, userdata, true);
        EndEntityInformation userdata2 = endEntityAccessSession.findUser(admin, userdata.getUsername());
        assertNotNull("findUser: " + userdata.getUsername(), userdata2);
    }

    private void createNewUser() throws Exception {
        // Make user that we know later...
        username1 = genRandomUserName(); 
        pwd1 = genRandomPwd();
        String email = username1 + "@anatom.se";
        endEntityManagementSession.addUser(internalAdmin, username1, pwd1, "C=SE, O=AnaTom, CN=" + username1, "rfc822name=" + email, email, false,
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
        log.debug("created user: " + username1 + ", " + pwd1 + ", C=SE, O=AnaTom, CN=" + username1);

        // Make another user that we know later...
        username2 = genRandomUserName();
        pwd2 = genRandomPwd();
        createUser(internalAdmin, username2, pwd2, caid, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, MAXFAILEDLOGINS);
        log.debug("created user: " + username2 + ", " + pwd2 + ", C=SE, O=AnaTom, CN=" + username2);
    }

    /** Tests authentication of users */
    @Test
    public void testAuthenticateUser() throws Exception {
        log.trace(">test02AuthenticateUser()");
        // user that we know exists...
        log.debug("Username:" + username1 + "\npwd:" + pwd1);
        EndEntityInformation data = authenticationSessionRemote.authenticateUser(internalAdmin, username1, pwd1);

        log.debug("DN: " + data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf(username1) != -1);

        log.debug("Email: " + data.getEmail());
        assertNotNull("Email should not be null", data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals(username1 + "@anatom.se"));

        log.debug("Type: " + data.getType());
        assertTrue("Type is wrong", data.getType().contains(EndEntityTypes.ENDUSER));
        log.trace("<test02AuthenticateUser()");
    }

    /** Tests filed authentication */
    @Test
    public void testFailAuthenticateUser() throws Exception {
        log.trace(">test03FailAuthenticateUser()");
        // Set status to GENERATED so authentication will fail
        endEntityManagementSession.setUserStatus(internalAdmin, username1, EndEntityConstants.STATUS_GENERATED, 0);
        boolean authfailed = false;
        try {
            EndEntityInformation auth = authenticationSessionRemote.authenticateUser(internalAdmin, username1, pwd1);
            log.debug("Authenticated user: " + auth.getUsername());
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.trace("<test03FailAuthenticateUser()");
    }

    /** Tests more failed authentication */
    @Test
    public void testFailAuthenticateUserWithWrongPassword() throws Exception {
        log.trace(">test04FailAuthenticateUser()");
        // user that we know exists... but we issue wrong password
        boolean authfailed = false;
        try {
            EndEntityInformation auth = authenticationSessionRemote.authenticateUser(internalAdmin, username1, "abc123");
            log.debug("Authenticated user: " + auth.getUsername());
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.trace("<test04FailAuthenticateUser()");
    }

    /** Test reset of key recovery mark. */
    @Test
    public void testUnmarkKeyRecoveryOnFinish() throws Exception {
        log.trace(">test05UnmarkKeyRecoveryOnFinish()");

        GlobalConfiguration config = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean orgkeyrecconfig = config.getEnableKeyRecovery();
        config.setEnableKeyRecovery(true);
        globalConfigurationSession.saveConfiguration(internalAdmin, config);

        // create certificate for user
        // Set status to NEW
        endEntityManagementSession.setPassword(internalAdmin, username1, "foo123");
        endEntityManagementSession.setUserStatus(internalAdmin, username1, EndEntityConstants.STATUS_NEW, 0);

        // Create a dummy certificate and keypair.
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, username1, "foo123", new PublicKeyWrapper(keys.getPublic()));

        // First mark the user for recovery
        keyRecoverySession.addKeyRecoveryData(internalAdmin, cert, username1, new KeyPairWrapper(keys));
        endEntityManagementSession.prepareForKeyRecovery(internalAdmin, username1, SecConst.EMPTY_ENDENTITYPROFILE, null);

        assertTrue("Failure the users keyrecovery session should have been marked", keyRecoverySession.isUserMarked(username1));

        // Now finish the user (The actual test)
        EndEntityInformation userdata = endEntityAccessSession.findUser(internalAdmin, username1);
        authenticationSessionRemote.finishUser(userdata);
        // And se if the user is still marked

        assertTrue("Failure the users keyrecovery session should have been unmarked", !keyRecoverySession.isUserMarked(username1));

        // Clean up
        keyRecoverySession.removeAllKeyRecoveryData(internalAdmin, username1);

        config.setEnableKeyRecovery(orgkeyrecconfig);
        globalConfigurationSession.saveConfiguration(internalAdmin, config);
        log.trace("<test05UnmarkKeyRecoveryOnFinish()");
    }

    /**
     * Tests that (maxNumFailedLogins-1) tries can be done and then after a
     * correct login the remainingLoginAttempts is reset so that
     * (maxNumFailedLogins) can be performed before the account is locked which
     * is then tested by trying to login using the correct password.
     */
    @Test
    public void testMultipleFailedLogins() throws Exception {
        log.trace(">test06FailedLoginsThenCorrect()");

        assertEquals(MAXFAILEDLOGINS, 4);

        // Test that we don't lock the account to early
        loginMaxNumFailedLoginsMinusOneAndThenOk(username2, pwd2);

        // Test that we lock the account
        loginUntilLocked(username2, pwd2);

        // Reset the status
        endEntityManagementSession.setUserStatus(internalAdmin, username2, EndEntityConstants.STATUS_NEW, 0);

        // After reset: Test that we don't lock the account to early
        loginMaxNumFailedLoginsMinusOneAndThenOk(username2, pwd2);

        // After reset: Test that we lock the account
        loginUntilLocked(username2, pwd2);

        log.trace("<test06FailedLoginsThenCorrect()");
    }

    private void loginMaxNumFailedLoginsMinusOneAndThenOk(String username, String password) throws Exception {
        // Login attempt: 1
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 2
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 3
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 4: This time with the right password which should work
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, password);
        } catch (AuthStatusException e) { // This time the status is wrong
            fail("The account shold not have been locked");
        } catch (AuthLoginException e) {
            fail("Authentication should have succeeded");
        }
    }

    private void loginUntilLocked(String username, String password) throws Exception {
        // Login attempt: 1
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 2
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 3
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 4
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, "_wrong-password_");
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthLoginException e) {
            // OK
        }
        // Login attempt: 5: This time with the right password but the account
        // should have been locked
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, password);
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthStatusException e) { // This time the status is wrong
            // OK
        }

        // Login attempt: 6: Should still be locked
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, password);
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthStatusException e) { // This time the status is wrong
            // OK
        }

        // Login attempt: 7: Should still be locked
        try {
            authenticationSessionRemote.authenticateUser(internalAdmin, username, password);
            fail("Authentication succeeded when it should have failed.");
        } catch (AuthStatusException e) { // This time the status is wrong
            // OK
        }
    }

    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

}
