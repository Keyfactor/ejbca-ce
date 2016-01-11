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
package org.ejbca.ui.cli;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CreateCertCommandTest {

    private static final String CA_DN = "CN=Test";
    private static final String USERNAME = "CreateCertCommandTest";
    private static final String PASSWORD = "foo123";

    private CreateCertCommand command = new CreateCertCommand();

    private File requestFile;
    private File resultFile;

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CreateCertCommandTest.class.getSimpleName());

    private X509CA ca;

    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        requestFile = File.createTempFile("test", null);
        resultFile = File.createTempFile("test", ".pem");
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        caSession.addCA(authenticationToken, ca);
        endEntityManagementSession.addUser(authenticationToken, USERNAME, PASSWORD, "CN=" + USERNAME, null, null, false,
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.TOKEN_SOFT_P12, 0, ca.getCAId());
        byte[] rawPkcs10req = caAdminSession.makeRequest(authenticationToken, ca.getCAId(), ca.getCertificateChain(), ca.getCAToken()
                .getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        FileOutputStream fileOutputStream = new FileOutputStream(requestFile);
        try {
            fileOutputStream.write(rawPkcs10req);
        } finally {
            fileOutputStream.close();
        }
    }

    @After
    public void tearDown() throws Exception {
        if (requestFile.exists()) {
            FileTools.delete(requestFile);
        }
        if (resultFile.exists()) {
            FileTools.delete(resultFile);
        }
        if (ca != null) {
            caSession.removeCA(authenticationToken, ca.getCAId());
        }
        endEntityManagementSession.deleteUser(authenticationToken, USERNAME);
    }

    @Test
    public void testCommand() throws CertificateException, IOException {
        String[] args = new String[] { USERNAME, PASSWORD, requestFile.getAbsolutePath(), resultFile.getAbsolutePath() };
        command.execute(args);
        Certificate result = CertTools.getCertsFromPEM(resultFile.getAbsolutePath(), Certificate.class).get(0);
        assertNotNull("No certificate was produced", result);

    }

}
