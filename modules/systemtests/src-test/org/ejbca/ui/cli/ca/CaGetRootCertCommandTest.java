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
package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CaGetRootCertCommandTest {

    private static final String CA_NAME = "CaGetRootCertCommandTest";
    private static final String CA_DN = "CN=" + CA_NAME;

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private X509CA ca;
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CaGetRootCertCommandTest.class.getSimpleName());

    private final CaGetRootCertCommand command = new CaGetRootCertCommand();
    private File resultFile;

    @Before
    public void setup() throws Exception {
        resultFile = File.createTempFile("test", null);
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        caSession.addCA(authenticationToken, ca);
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        if (resultFile != null) {
            FileTools.delete(resultFile);
        }
        if (ca != null) {
            caSession.removeCA(authenticationToken, ca.getCAId());
        }
    }

    @Test
    public void testCommand() throws ErrorAdminCommandException, CertificateException, IOException {
        String[] args = new String[] { ca.getName(), resultFile.getAbsolutePath() };
        command.execute(args);
        Certificate result = CertTools.getCertsFromPEM(resultFile.getAbsolutePath()).get(0);
        assertNotNull("No certificate was produced.", result);
        assertTrue("Root cert was not delivered.", ca.getCACertificate().equals(result));
    }

}
