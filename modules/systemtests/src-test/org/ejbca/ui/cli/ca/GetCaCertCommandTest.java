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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * @version $Id$
 *
 */
public class GetCaCertCommandTest {
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);

    private static final String RESULT_FILENAME = "result.pem";
    private static X509CA rootCa;
    private static  X509CAInfo cainfo;
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(GetCaCertCommandTest.class.getSimpleName());

    private final GetCaCertCommand command = new GetCaCertCommand();

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();
    
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        rootCa = CaTestUtils.createTestX509CA("CN=GetCaCertCommandTestRoot", null, false);
        caSession.addCA(authenticationToken, rootCa);
        cainfo = new X509CAInfo("CN=GetCaCertCommandTestSub", "GetCaCertCommandTestSub", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, 3650, rootCa.getCAId(), rootCa.getCertificateChain(), rootCa.getCAToken());
        caAdminSession.createCA(authenticationToken, cainfo);
        
    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {

        if (rootCa != null) {
            caSession.removeCA(authenticationToken, rootCa.getCAId());
        }
        if(cainfo != null) {
            caSession.removeCA(authenticationToken, cainfo.getCAId());
        }
    }

    @Test
    public void testCommandGetRootCert() throws CertificateException, IOException {
        File resultFile = testFolder.newFile(RESULT_FILENAME);
        String[] args = new String[] { rootCa.getName(), resultFile.getAbsolutePath()};
        command.execute(args);
        Certificate result = CertTools.getCertsFromPEM(resultFile.getAbsolutePath(), Certificate.class).get(0);
        assertNotNull("No certificate was produced.", result);
        assertTrue("Root cert was not delivered.", rootCa.getCACertificate().equals(result));
    }
    
    @Test
    public void testCommandGetSubCert() throws CertificateException, IOException, CADoesntExistsException, AuthorizationDeniedException {
        File resultFile = testFolder.newFile(RESULT_FILENAME);
        String[] args = new String[] { cainfo.getName(), resultFile.getAbsolutePath()};
        command.execute(args);
        Certificate result = CertTools.getCertsFromPEM(resultFile.getAbsolutePath(), Certificate.class).get(0);
        assertNotNull("No certificate was produced.", result);
        assertTrue("SubCa cert was not delivered.", new ArrayList<Certificate>( caSession.getCAInfo(authenticationToken, cainfo.getCAId()).getCertificateChain()).get(0).equals(result));
    }

}
