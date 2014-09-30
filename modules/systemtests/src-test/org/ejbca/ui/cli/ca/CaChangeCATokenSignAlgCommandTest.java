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
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.util.AlgorithmConstants;
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
public class CaChangeCATokenSignAlgCommandTest {

    private static final String CA_NAME = "CaChangeCATokenSignAlgCommandTest";
    private static final String CA_DN = "CN=" + CA_NAME;
    
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CaActivateCACommandTest.class.getSimpleName());

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    
    private CaChangeCATokenSignAlgCommand command = new CaChangeCATokenSignAlgCommand();
    private X509CA ca;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        //Creates a CA with AlgorithmConstants.SIGALG_SHA256_WITH_RSA
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
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
        String[] args = new String[] { CA_NAME, AlgorithmConstants.SIGALG_SHA1_WITH_RSA };
        command.execute(args);
        CAInfo result = caSession.getCAInfo(authenticationToken, ca.getCAId());
        assertEquals("Signing algorithm was not changed", AlgorithmConstants.SIGALG_SHA1_WITH_RSA, result.getCAToken().getSignatureAlgorithm());
    }
}
