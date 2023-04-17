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

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Collection;
import java.util.Iterator;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 * System test class for CaEditCaCommand
 * 
 * @version $Id$
 */
public class CaEditCaCommandTest {

    private static final String CA_NAME = "CaEditCaCommandTest";
    private static final String[] HAPPY_PATH_ARGS = { CA_NAME, "CRLPeriod", "2592000000"};
    private static final String[] HAPPY_PATH_SINGLEARRAY_ARGS = { CA_NAME, "validators", "123"};
    private static final String[] HAPPY_PATH_MULTIARRAY_ARGS = { CA_NAME, "validators", "123;234"};
    private static final String[] HAPPY_PATH_EMPTYARRAY_ARGS = { CA_NAME, "validators", ""};

    private CaEditCaCommand caEditCommand;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaEditCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    
    int caid = 0;

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caEditCommand = new CaEditCaCommand();
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.createTestCA(CA_NAME);
        caid = caSession.getCAInfo(admin, CA_NAME).getCAId();
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(caid);
    }

    /** Test trivial happy path for execute, i.e, edit an ordinary CA. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        CAInfo info = caSession.getCAInfo(admin, CA_NAME);
        assertEquals("CRLPeriod of a newly created default CA is incorrect, did default value change?", 86400000L, info.getCRLPeriod());
        caEditCommand.execute(HAPPY_PATH_ARGS);
        info = caSession.getCAInfo(admin, CA_NAME);
        assertEquals("CRLPeriod of a edited CA is incorrect. Edit did not work?", 2592000000L, info.getCRLPeriod());
    }

    /** Test trivial happy path for setting an array of values, validators. */
    @Test
    public void testExecuteHappyPathArrays() throws Exception {
        CAInfo info = caSession.getCAInfo(admin, CA_NAME);
        assertEquals("Validators of a newly created default CA is incorrect, did default value change?", 0, info.getValidators().size());
        caEditCommand.execute(HAPPY_PATH_SINGLEARRAY_ARGS);
        info = caSession.getCAInfo(admin, CA_NAME);
        Collection<Integer> validators = info.getValidators();
        assertEquals("Validators of a edited CA didn't set the right number of values (1). Edit did not work?", 1, validators.size());
        assertEquals("Validators of a edited CA didn't set the right value.", 123, validators.iterator().next().intValue());
        caEditCommand.execute(HAPPY_PATH_MULTIARRAY_ARGS);
        info = caSession.getCAInfo(admin, CA_NAME);
        validators = info.getValidators();
        assertEquals("Validators of a edited CA didn't set the right number of values (2). Edit did not work?", 2, validators.size());
        Iterator<Integer> iter = validators.iterator();
        assertEquals("Validators of a edited CA didn't set the right value.", 123, iter.next().intValue());
        assertEquals("Validators of a edited CA didn't set the right value.", 234, iter.next().intValue());
        caEditCommand.execute(HAPPY_PATH_EMPTYARRAY_ARGS);
        info = caSession.getCAInfo(admin, CA_NAME);
        validators = info.getValidators();
        assertEquals("Validators of a edited CA didn't set the right number of values (0). Edit did not work?", 0, validators.size());
    }

    @Test
    public void testRenameCa() throws AuthorizationDeniedException {
        final String newName = "CaEditCaCommandTestNewName";
        final String[] changeCaNameArgs = { CA_NAME, "name", newName };
        caEditCommand.execute(changeCaNameArgs);
        CAInfo info = caSession.getCAInfo(admin, caid);
        assertNotNull("CA could not be found after name change", info);
        assertEquals("CA name change did not happen.", newName, info.getName());
    }
    
}
