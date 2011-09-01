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

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaInitCommandTest
 * 
 * @version $Id$
 */
public class CaInitCommandTest {

    private static final String CA_NAME = "1327ca2";
    private static final String CERTIFICATE_PROFILE_NAME = "certificateProfile1327";
    private static final String[] HAPPY_PATH_ARGS = { "init", CA_NAME, "\"CN=CLI Test CA 1237ca2,O=EJBCA,C=SE\"", "soft", "foo123", "2048", "RSA",
            "365", "null", "SHA1WithRSA" };
    private static final String[] ROOT_CA_ARGS = { "init", CA_NAME, "\"CN=CLI Test CA 1237ca2,O=EJBCA,C=SE\"", "soft", "foo123", "2048", "RSA",
            "365", "null", "SHA1WithRSA", "-certprofile", "ROOTCA" };
    private static final String[] CUSTOM_PROFILE_ARGS = { "init", CA_NAME, "\"CN=CLI Test CA 1237ca2,O=EJBCA,C=SE\"", "soft", "foo123", "2048",
            "RSA", "365", "null", "SHA1WithRSA", "-certprofile", CERTIFICATE_PROFILE_NAME };

    private CaInitCommand caInitCommand;
    private AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CertificateProfileSessionRemote certificateProfileSessionRemote = InterfaceCache.getCertificateProfileSession();

    @Before
    public void setUp() throws Exception {
        caInitCommand = new CaInitCommand();
        try {
            caSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        } catch (Exception e) {
            // Ignore.

        }
    }

    @After
    public void tearDown() throws Exception {
    }

    /**
     * Test trivial happy path for execute, i.e, create an ordinary CA.
     * 
     * @throws Exception
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testExecuteHappyPath() throws Exception {
        try {
            caInitCommand.execute(HAPPY_PATH_ARGS);
            assertNotNull("Happy path CA was not created.", caSession.getCAInfo(admin, CA_NAME));
        } finally {
            caSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }
    }

    @Test
    public void testExecuteWithRootCACertificateProfile() throws Exception {
        try {
            caInitCommand.execute(ROOT_CA_ARGS);
            assertNotNull("CA was not created using ROOTCA certificate profile.", caSession.getCAInfo(admin, CA_NAME));
        } finally {
            caSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }
    }

    @Test
    public void testExecuteWithCustomCertificateProfile() throws CertificateProfileExistsException, ErrorAdminCommandException,
            AuthorizationDeniedException, CADoesntExistsException {
        if (certificateProfileSessionRemote.getCertificateProfile(CERTIFICATE_PROFILE_NAME) == null) {
            CertificateProfile certificateProfile = new CertificateProfile();
            certificateProfileSessionRemote.addCertificateProfile(admin, CERTIFICATE_PROFILE_NAME, certificateProfile);
        }
        try {
            CertificateProfile apa = certificateProfileSessionRemote.getCertificateProfile(CERTIFICATE_PROFILE_NAME);
            assertNotNull(apa);
            caInitCommand.execute(CUSTOM_PROFILE_ARGS);

            // Following line should throw an exception.
            boolean caught = false;
            try {
                caSession.getCAInfo(admin, CA_NAME);              
            } catch (CADoesntExistsException e) {
                caught = true;
            }
            Assert.assertTrue("CA was created using created using non ROOTCA or SUBCA certificate profile.", caught);

        } finally {
            certificateProfileSessionRemote.removeCertificateProfile(admin, CERTIFICATE_PROFILE_NAME);
        }
    }

}
