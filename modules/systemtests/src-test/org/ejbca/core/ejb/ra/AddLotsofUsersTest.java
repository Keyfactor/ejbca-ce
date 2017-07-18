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

package org.ejbca.core.ejb.ra;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.lang.time.StopWatch;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Creates tons of end entities. The baseline should be the user creation time for a single thread using an always allow token (forgoing database 
 * checks), while this test should press the database to the point where caching influences behavior. 
 *
 * @version $Id$
 */
public class AddLotsofUsersTest extends CaTestCase {

	private static final Logger log = Logger.getLogger(AddLotsofUsersTest.class);

	private static final String USERNAME_PREFIX = "AddLotsofUsersTest";
	private static final int NUMBER_OF_THREADS = 10;
	private static final int USERS_PER_THREAD = 100;
	
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AddLotsofUsersTest"));

    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public String getRoleName() {
        return "AddLotsofUsersTest"; 
    }

    @Test
    public void testCreateManyUsers() throws Exception {
        final StopWatch stopWatch = new StopWatch();
        List<RaEntity> tasks = new ArrayList<>();
        List<String> createdUsers = new ArrayList<>();
        for(int i = 0; i < NUMBER_OF_THREADS; i++) {
            tasks.add(new RaEntity(i, USERS_PER_THREAD));
        }
        ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_THREADS);
        stopWatch.start();
        try {
            List<Future<String[]>> futures = executor.invokeAll(tasks);
            for(Future<String[]> future : futures) {
                createdUsers.addAll(Arrays.asList(future.get()));
            }
            stopWatch.stop();
            long diff = stopWatch.getTime();
            log.info(createdUsers.size() + " end entities have been generated. Total time: " + diff + " ms."); 
            log.info("Average creation time: " + diff / (NUMBER_OF_THREADS * USERS_PER_THREAD) + " ms per end entity");
        } finally {
            for (String endEntityName : createdUsers) {
                try {
                    endEntityManagementSession.deleteUser(alwaysAllowToken, endEntityName);
                } catch (NoSuchEndEntityException e) {
                    //NOPMD Ignore
                }
            }
        }
    }
    
    private class RaEntity implements Callable<String[]> {

        private final int endEntitiesPerThread;
        private final String[] usernames;
        private final int threadNumber;
        
        public RaEntity(int threadNumber, int endEntitiesPerThread) {
            this.threadNumber = threadNumber;
            this.endEntitiesPerThread = endEntitiesPerThread;
            this.usernames = new String[endEntitiesPerThread];
        }

        @Override
        public String[] call() throws Exception {
            String theadUsername = USERNAME_PREFIX + "_" + threadNumber;
            for (int i = 0; i < endEntitiesPerThread; i++) {
                String username = theadUsername + "_" + i;
                usernames[i] = username;
                endEntityManagementSession.addUser(roleMgmgToken, username, "foo123", "CN=" + username, null, null, false,
                        SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                        EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, getTestCAId());

            }
            return usernames;
        }
    }
    
}
