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

package org.ejbca.ui.cli.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.ejb.RemoveException;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for RA addendentity and setpwd commands
 * 
 * @version $Id$
 */
public class AddEndEntityCommandTest {

    private static final String USER_NAME = "RaSetPwdCommandTest_user1";
    private static final String USER_NAME_INVALID = "RaSetPwdCommandTest_user12";
    private static final String CA_NAME = "TestCA";
    private static final String[] HAPPY_PATH_ADD_ARGS = { USER_NAME, "--password", "foo123", "CN="+USER_NAME+"", CA_NAME, "1", "PEM" };
    private static final String[] HAPPY_PATH_SETPWD_ARGS = { USER_NAME, "--password", "bar123" };
    private static final String[] HAPPY_PATH_SETCLEARPWD_ARGS = { USER_NAME, "--password", "foo123bar" };
    private static final String[] INVALIDUSER_PATH_SETPWDPWD_ARGS = { USER_NAME_INVALID, "--password", "foo123bar" };
    private static final String[] INVALIDUSER_PATH_SETCLEARPWD_ARGS = { USER_NAME_INVALID, "--password", "foo123bar" };

    private AddEndEntityCommand command0;
    private SetPasswordCommand command1;
    private SetCleartextPasswordCommand command2;
    private CA testx509ca;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RaSetPwdCommandTest"));

    private EndEntityManagementSessionRemote eeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        testx509ca = CaTestUtils.createTestX509CA("CN=" + CA_NAME, null, false, keyusage);
        caSession.addCA(admin, testx509ca);
        
        command0 = new AddEndEntityCommand();
        command1 = new SetPasswordCommand();
        command2 = new SetCleartextPasswordCommand();
    }
    
    @After
    public void tearDown() throws Exception {
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(admin, testx509ca.getCAId());
    }

    @Test
    public void testExecuteHappyPath() throws IllegalQueryException, UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException,
            NoSuchEndEntityException, RemoveException {

        try {
            assertEquals(CommandResult.SUCCESS, command0.execute(HAPPY_PATH_ADD_ARGS));
            Query query = new Query(Query.TYPE_USERQUERY);
            query.add(UserMatch.MATCH_WITH_USERNAME, BasicMatch.MATCH_TYPE_EQUALS, USER_NAME);
            String caauthstring = null;
            String eeprofilestr = null;
            Collection<EndEntityInformation> col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.CREATE_END_ENTITY);
            assertEquals(1, col.size());
            EndEntityInformation eei = col.iterator().next();
            assertEquals("CN="+USER_NAME, eei.getDN());
            assertNull("getPassword returns "+eei.getPassword(), eei.getPassword());
            assertTrue(eeSession.verifyPassword(admin, USER_NAME, "foo123"));
            
            command1.execute(HAPPY_PATH_SETPWD_ARGS);
            col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.CREATE_END_ENTITY);
            assertEquals(1, col.size());
            eei = col.iterator().next();
            assertEquals("CN="+USER_NAME, eei.getDN());
            assertNull("getPassword returns "+eei.getPassword(), eei.getPassword());
            assertTrue(eeSession.verifyPassword(admin, USER_NAME, "bar123"));
            assertFalse(eeSession.verifyPassword(admin, USER_NAME, "foo123"));

            command2.execute(HAPPY_PATH_SETCLEARPWD_ARGS);
            col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.CREATE_END_ENTITY);
            assertEquals(1, col.size());
            eei = col.iterator().next();
            assertEquals("CN="+USER_NAME, eei.getDN());
            assertEquals("foo123bar", eei.getPassword());
            assertTrue(eeSession.verifyPassword(admin, USER_NAME, "foo123bar"));
            assertFalse(eeSession.verifyPassword(admin, USER_NAME, "bar123"));
        } finally {
            try {
                eeSession.deleteUser(admin, USER_NAME);
            } catch (NoSuchEndEntityException e) {} // NOPMD: user does not exist, some error failed above           
        }  
    }


    @Test
    public void testSetPwdInvalidUser() throws IllegalQueryException, AuthorizationDeniedException, RemoveException, UserDoesntFullfillEndEntityProfile, NoSuchEndEntityException {

        try {

            command0.execute(HAPPY_PATH_ADD_ARGS);
            Query query = new Query(Query.TYPE_USERQUERY);
            query.add(UserMatch.MATCH_WITH_USERNAME, BasicMatch.MATCH_TYPE_EQUALS, USER_NAME);
            String caauthstring = null;
            String eeprofilestr = null;
            Collection<EndEntityInformation> col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.CREATE_END_ENTITY);
            assertEquals(1, col.size());
            EndEntityInformation eei = col.iterator().next();
            assertEquals("CN="+USER_NAME, eei.getDN());
            assertNull("getPassword returns "+eei.getPassword(), eei.getPassword());
            assertTrue(eeSession.verifyPassword(admin, USER_NAME, "foo123"));

            // Append our test appender to the commands logger, so we can check the output of the command 
            // after running
            final TestAppender appender1 = new TestAppender();
            final Logger logger1 = command1.getLogger();
            logger1.addAppender(appender1);
            command1.execute(INVALIDUSER_PATH_SETPWDPWD_ARGS);
            col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.CREATE_END_ENTITY);
            assertEquals(1, col.size());
            eei = col.iterator().next();
            assertEquals("CN="+USER_NAME, eei.getDN());
            assertNull("getPassword returns "+eei.getPassword(), eei.getPassword());
            // Password should not have changed
            assertTrue(eeSession.verifyPassword(admin, USER_NAME, "foo123"));
            assertFalse(eeSession.verifyPassword(admin, USER_NAME, "bar123"));
            // Verify that we had a nice error message that the user did not exist
            List<LoggingEvent> log = appender1.getLog();
            assertEquals("End entity with username '"+USER_NAME_INVALID+"' does not exist.", log.get(1).getMessage());

            // Append our test appender to the commands logger, so we can check the output of the command 
            // after running
            final TestAppender appender2 = new TestAppender();
            final Logger logger2 = command2.getLogger();
            logger2.addAppender(appender2);
            command2.execute(INVALIDUSER_PATH_SETCLEARPWD_ARGS);
            col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.CREATE_END_ENTITY);
            assertEquals(1, col.size());
            eei = col.iterator().next();
            assertEquals("CN="+USER_NAME, eei.getDN());
            assertNull("getPassword returns "+eei.getPassword(), eei.getPassword());
            // Password should not have changed
            assertTrue(eeSession.verifyPassword(admin, USER_NAME, "foo123"));
            assertFalse(eeSession.verifyPassword(admin, USER_NAME, "foo123bar"));
            // Verify that we had a nice error message that the user did not exist
            log = appender2.getLog();
            assertEquals("End entity with username '"+USER_NAME_INVALID+"' does not exist.", log.get(1).getMessage());
        } finally {
            try {
                eeSession.deleteUser(admin, USER_NAME);
            } catch (NoSuchEndEntityException e) {} // NOPMD: user does not exist, some error failed above           
        }    
    }
    
    class TestAppender extends AppenderSkeleton {
        private final List<LoggingEvent> log = new ArrayList<LoggingEvent>();

        @Override
        public boolean requiresLayout() {
            return false;
        }

        @Override
        protected void append(final LoggingEvent loggingEvent) {
            log.add(loggingEvent);
        }

        @Override
        public void close() {
        }

        public List<LoggingEvent> getLog() {
            return new ArrayList<LoggingEvent>(log);
        }
    }


}
