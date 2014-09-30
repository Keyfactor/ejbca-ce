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

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CaDeactivateCACommandTest {

    private static final String CA_NAME = "CaDeactivateCACommandTest";
    private static final String CA_DN = "CN=" + CA_NAME;

    private final CaDeactivateCACommand command = new CaDeactivateCACommand();

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private X509CA ca;
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CaChangeCertProfileCommand.class.getSimpleName());

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        ca.setStatus(CAConstants.CA_ACTIVE);
        caSession.addCA(authenticationToken, ca);
    }

    @After
    public void tearDown() throws Exception {
        if (ca != null) {
            caSession.removeCA(authenticationToken, ca.getCAId());
        }
    }

    @Test
    public void testCommand() throws CADoesntExistsException, AuthorizationDeniedException {
        String[] args = new String[] { CA_NAME };
        command.execute(args);
        CAInfo result = caSession.getCAInfo(authenticationToken, ca.getCAId());
        assertEquals("CA was not deactivated.", CAConstants.CA_OFFLINE, result.getStatus());

    }
}
