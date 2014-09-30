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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaEditCaCommand
 * 
 * @version $Id$
 */
public class CaEditCaCommandTest {

    private static final String CA_NAME = "1327editca2";
    private static final String[] HAPPY_PATH_ARGS = { CA_NAME, "CRLPeriod", "2592000000"};

    private CaEditCaCommand caEditCommand;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaEditCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caEditCommand = new CaEditCaCommand();
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.createTestCA(CA_NAME);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
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
    
}
