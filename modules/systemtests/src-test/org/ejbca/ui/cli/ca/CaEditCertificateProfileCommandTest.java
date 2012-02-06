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
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CA EditCertificateProfile command
 * 
 * @version $Id$
 */
public class CaEditCertificateProfileCommandTest {

    private static final String PROFILE_NAME = "1327profile2";
    private static final String[] HAPPY_PATH_ARGS1 = { "editcertificateprofile", PROFILE_NAME, "CRLDistributionPointURI=http://my-crl-distp.com/my.crl" };
    private static final String[] HAPPY_PATH_ARGS2 = { "editcertificateprofile", PROFILE_NAME, "-paramType", "java.util.List", "CaIssuers=http://my-ca.issuer.com/ca"};
    private static final String[] MISSING_ARGS = { "editcertificateprofile", PROFILE_NAME };
    private static final String[] INVALID_FIELD_ARGS = { "editcertificateprofile", PROFILE_NAME, "hostname=myhost.com" };

    private CaEditCertificateProfileCommand command;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaEditCertificateProfileCommandTest"));

    private CertificateProfileSessionRemote profileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        command = new CaEditCertificateProfileCommand();
        try {
            profileSession.removeCertificateProfile(admin, PROFILE_NAME);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
    }

    @Test
    public void testExecuteHappyPath() throws Exception {
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            profile.setCRLDistributionPointURI("http://crl1.foo.com/crl1.crl");
            List<String> caissuers = new ArrayList<String>();
            caissuers.add("ldap://caissuer.foo.com/ca1.der");
            profile.setCaIssuers(caissuers);
            profileSession.addCertificateProfile(admin, PROFILE_NAME, profile);
            CertificateProfile profile1 = profileSession.getCertificateProfile(PROFILE_NAME);
            assertEquals("storing cert profile with values failed", "http://crl1.foo.com/crl1.crl", profile1.getCRLDistributionPointURI());
            assertEquals("storing cert profile with values failed", "ldap://caissuer.foo.com/ca1.der", profile1.getCaIssuers().get(0));
            command.execute(HAPPY_PATH_ARGS1);
            command.execute(HAPPY_PATH_ARGS2);
            // Check that we edited
            CertificateProfile profile2 = profileSession.getCertificateProfile(PROFILE_NAME);
            assertEquals("changing cert profile with values failed", "http://my-crl-distp.com/my.crl", profile2.getCRLDistributionPointURI());
            assertEquals("changing cert profile with values failed", "http://my-ca.issuer.com/ca", profile2.getCaIssuers().get(0));
        } finally {
            profileSession.removeCertificateProfile(admin, PROFILE_NAME);
        }
    }

    @Test
    public void testExecuteWithMissingArgs() throws Exception {
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            profile.setCRLDistributionPointURI("http://crl1.foo.com/crl1.crl");
            List<String> caissuers = new ArrayList<String>();
            caissuers.add("ldap://caissuer.foo.com/ca1.der");
            profile.setCaIssuers(caissuers);
            profileSession.addCertificateProfile(admin, PROFILE_NAME, profile);
            CertificateProfile profile1 = profileSession.getCertificateProfile(PROFILE_NAME);
            assertEquals("storing cert profile with values failed", "http://crl1.foo.com/crl1.crl", profile1.getCRLDistributionPointURI());
            assertEquals("storing cert profile with values failed", "ldap://caissuer.foo.com/ca1.der", profile1.getCaIssuers().get(0));
            command.execute(MISSING_ARGS);
            // Check that nothing happened
            CertificateProfile profile2 = profileSession.getCertificateProfile(PROFILE_NAME);
            assertEquals("storing cert profile with values failed", "http://crl1.foo.com/crl1.crl", profile2.getCRLDistributionPointURI());
            assertEquals("storing cert profile with values failed", "ldap://caissuer.foo.com/ca1.der", profile2.getCaIssuers().get(0));
        } finally {
            profileSession.removeCertificateProfile(admin, PROFILE_NAME);
        }
    }

    @Test
    public void testExecuteWithInvalidField() throws Exception {
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            profile.setCRLDistributionPointURI("http://crl1.foo.com/crl1.crl");
            profileSession.addCertificateProfile(admin, PROFILE_NAME, profile);
            CertificateProfile profile1 = profileSession.getCertificateProfile(PROFILE_NAME);
            assertEquals("storing cert profile with values failed", "http://crl1.foo.com/crl1.crl", profile1.getCRLDistributionPointURI());
            command.execute(INVALID_FIELD_ARGS);
            fail("This should have thrown an exception");
        } catch (ErrorAdminCommandException e) {
            assertEquals("org.ejbca.ui.cli.ErrorAdminCommandException: Method 'getHostname' does not exist. Did you use correct case for every character of the field?", e.getMessage());
        } finally {
            profileSession.removeCertificateProfile(admin, PROFILE_NAME);
        }
    }

    
}
