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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.ui.cli.ErrorAdminCommandException;
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
    private static final String[] HAPPY_PATH_ARGS = { "init", CA_NAME, "CN=CLI Test CA 1237ca2,O=EJBCA,C=SE", "soft", "foo123", "2048", "RSA",
            "365", "null", "SHA1WithRSA" };
    private static final String[] X509_TYPE_ARGS = { "init", CA_NAME, "CN=CLI Test CA 1237ca2,O=EJBCA,C=SE", "soft", "foo123", "2048", "RSA",
        "365", "null", "SHA1WithRSA", "-type", "x509" };
    private static final String[] X509_ARGS_NON_DEFULTPWD = { "init", CA_NAME, "CN=CLI Test CA 1237ca2,O=EJBCA,C=SE", "soft", "bar123", "2048", "RSA",
        "365", "1.1.1.1", "SHA1WithRSA" };
    private static final String[] CVC_TYPE_ARGS = { "init", CA_NAME, "CN=CVCCATEST,O=EJBCA,C=AZ ", "soft", "foo123", "2048", "RSA",
        "365", "null", "SHA1WithRSA", "-type", "cvc" };
    private static final String[] ROOT_CA_ARGS = { "init", CA_NAME, "CN=CLI Test CA 1237ca2,O=EJBCA,C=SE", "soft", "foo123", "2048", "RSA",
            "365", "null", "SHA1WithRSA", "-certprofile", "ROOTCA" };
    private static final String[] CUSTOM_PROFILE_ARGS = { "init", CA_NAME, "CN=CLI Test CA 1237ca2,O=EJBCA,C=SE", "soft", "foo123", "2048",
            "RSA", "365", "null", "SHA1WithRSA", "-certprofile", CERTIFICATE_PROFILE_NAME };

    private CaInitCommand caInitCommand;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaInitCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        caInitCommand = new CaInitCommand();
        CaTestCase.removeTestCA(CA_NAME);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
    }

    /** Test trivial happy path for execute, i.e, create an ordinary CA. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        caInitCommand.execute(HAPPY_PATH_ARGS);
        assertNotNull("Happy path CA was not created.", caSession.getCAInfo(admin, CA_NAME));
    }
    
    @Test
    public void testWithX509Type() throws Exception{
        caInitCommand.execute(X509_TYPE_ARGS);
        assertNotNull("X509 typed CA was not created.", caSession.getCAInfo(admin, CA_NAME));
    }

    @Test
    public void testWithX509TypeNonDefaultPwd() throws Exception{
        caInitCommand.execute(X509_ARGS_NON_DEFULTPWD);
        assertNotNull("X509 typed CA with non default CA token pwd was not created.", caSession.getCAInfo(admin, CA_NAME));
    }

    @Test
    public void testWithCVCType() throws Exception{
        caInitCommand.execute(CVC_TYPE_ARGS);
        CAInfo caInfo = caSession.getCAInfo(admin, CA_NAME);
        assertNotNull("CVC typed CA was not created.", caInfo);
        assertEquals("CAInfo was not of type CVC", caInfo.getCAType(), CAInfo.CATYPE_CVC);        
    }
    
    @Test
    public void testExecuteWithRootCACertificateProfile() throws Exception {
        caInitCommand.execute(ROOT_CA_ARGS);
        assertNotNull("CA was not created using ROOTCA certificate profile.", caSession.getCAInfo(admin, CA_NAME));
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
