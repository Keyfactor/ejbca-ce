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

import java.util.ArrayList;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CA EditCertificateProfile command
 * 
 * @version $Id$
 */
public class CaEditCertificateProfileCommandTest {

    private static final String PROFILE_NAME = "1327profile2";
    private static final String[] HAPPY_PATH_ARGS1 = { PROFILE_NAME, "CRLDistributionPointURI", "--value", "http://my-crl-distp.com/my.crl" };
    private static final String[] HAPPY_PATH_ARGS2 = { PROFILE_NAME, "caIssuers", "--value", "http://my-ca.issuer.com/ca" };
    private static final String[] HAPPY_PATH_ARGS3 = { PROFILE_NAME, "useOcspNoCheck", "--value", "true" };

    private static final String[] HAPPY_PATH_GETVALUE_ARGS = { PROFILE_NAME, "-getValue", "caIssuers" };
    private static final String[] HAPPY_PATH_LISTFIELDS_ARGS = { PROFILE_NAME, "-listFields" };
    private static final String[] MISSING_ARGS = { PROFILE_NAME };
    private static final String[] INVALID_FIELD_ARGS = { PROFILE_NAME, "hostname", "myhost.com" };

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
            assertEquals("Storing cert profile with values failed", "http://crl1.foo.com/crl1.crl", profile1.getCRLDistributionPointURI());
            assertEquals("Storing cert profile with values failed", "ldap://caissuer.foo.com/ca1.der", profile1.getCaIssuers().get(0));
            assertEquals("Changing cert profile with values failed", false, profile1.getUseOcspNoCheck());
            command.execute(HAPPY_PATH_ARGS1);
            command.execute(HAPPY_PATH_ARGS2);
            command.execute(HAPPY_PATH_ARGS3);
            // Check that we edited
            CertificateProfile profile2 = profileSession.getCertificateProfile(PROFILE_NAME);
            assertEquals("Changing cert profile with values failed", "http://my-crl-distp.com/my.crl", profile2.getCRLDistributionPointURI());
            assertEquals("Changing cert profile with values failed", "http://my-ca.issuer.com/ca", profile2.getCaIssuers().get(0));
            assertEquals("Changing cert profile with values failed", true, profile2.getUseOcspNoCheck());
            // Try to get value and list fields without exceptions...
            command.execute(HAPPY_PATH_GETVALUE_ARGS);
            command.execute(HAPPY_PATH_LISTFIELDS_ARGS);
        } finally {
            profileSession.removeCertificateProfile(admin, PROFILE_NAME);
        }
    }

    @Test
    public void testChangeAvailableCas() throws AuthorizationDeniedException, CertificateProfileExistsException {
        final String[] availableCasArguments = { PROFILE_NAME, "availableCAs", "--value", "-1" };     
        try {
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            profileSession.addCertificateProfile(admin, PROFILE_NAME, profile);
            command.execute(availableCasArguments);
            // Check that we edited
            CertificateProfile retrievedProfile = profileSession.getCertificateProfile(PROFILE_NAME);
            List<Integer> availableCas = retrievedProfile.getAvailableCAs();
            assertEquals("Changing availble CAs failed", 1, availableCas.size());
            assertEquals("Changing availble CAs failed", Integer.valueOf(-1), availableCas.get(0));
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
            assertEquals(CommandResult.CLI_FAILURE, command.execute(MISSING_ARGS));
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
            //TODO: Make sure that Certificate Profile is identical afterwards.
        } finally {
            profileSession.removeCertificateProfile(admin, PROFILE_NAME);
        }
    }

}
