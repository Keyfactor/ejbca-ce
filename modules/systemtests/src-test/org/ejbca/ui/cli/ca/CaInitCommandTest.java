package org.ejbca.ui.cli.ca;

import junit.framework.TestCase;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.InterfaceCache;

/**
 * System test class for CaInitCommandTest
 * 
 * @author mikek
 * @version $Id$
 */
public class CaInitCommandTest extends TestCase {

    private static final String CA_NAME = "1327ca2";
    private static final String CERTIFICATE_PROFILE_NAME = "certificateProfile1327";
    private static final String[] HAPPY_PATH_ARGS = { "init", CA_NAME, "\"CN=CLI Test CA 1237ca2,O=EJBCA,C=SE\"", "soft", "foo123", "2048", "RSA", "365",
            "null", "SHA1WithRSA" };
    private static final String[] ROOT_CA_ARGS = { "init", CA_NAME, "\"CN=CLI Test CA 1237ca2,O=EJBCA,C=SE\"", "soft", "foo123", "2048", "RSA", "365", "null",
            "SHA1WithRSA", "-certprofile", "ROOTCA" };
    private static final String[] CUSTOM_PROFILE_ARGS = { "init", CA_NAME, "\"CN=CLI Test CA 1237ca2,O=EJBCA,C=SE\"", "soft", "foo123", "2048", "RSA", "365",
            "null", "SHA1WithRSA", "-certprofile", CERTIFICATE_PROFILE_NAME };

    private CaInitCommand caInitCommand;
    private AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));
    
    private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private CertificateProfileSessionRemote certificateProfileSessionRemote = InterfaceCache.getCertificateProfileSession();

    /**
     * Test trivial happy path for execute, i.e, create an ordinary CA.
     * 
     * @throws Exception
     * @throws AuthorizationDeniedException
     */
    public void testExecuteHappyPath() throws Exception {
        try {
            caInitCommand.execute(HAPPY_PATH_ARGS);
            assertNotNull("Happy path CA was not created.", caSession.getCAInfo(admin, CA_NAME));
        } finally {
            caSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }
    }

    public void testExecuteWithRootCACertificateProfile() throws Exception {
        try {
            caInitCommand.execute(ROOT_CA_ARGS);
            assertNotNull("CA was not created using ROOTCA certificate profile.", caSession.getCAInfo(admin, CA_NAME));
        } finally {
            caSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }
    }

    public void testExecuteWithCustomCertificateProfile() throws CertificateProfileExistsException, ErrorAdminCommandException, AuthorizationDeniedException, CADoesntExistsException {
        if (certificateProfileSessionRemote.getCertificateProfile(CERTIFICATE_PROFILE_NAME) == null) {
            CertificateProfile certificateProfile = new CertificateProfile();
            certificateProfileSessionRemote.addCertificateProfile(admin, CERTIFICATE_PROFILE_NAME, certificateProfile);
        }
        try {
            CertificateProfile apa = certificateProfileSessionRemote.getCertificateProfile(CERTIFICATE_PROFILE_NAME);
            assertNotNull(apa);
            caInitCommand.execute(CUSTOM_PROFILE_ARGS);
            assertNull("CA was created using created using non ROOTCA or SUBCA certificate profile.", caSession.getCAInfo(admin, CA_NAME));
        } finally {
            certificateProfileSessionRemote.removeCertificateProfile(admin, CERTIFICATE_PROFILE_NAME);
        }
    }

    public void setUp() throws Exception {
        caInitCommand = new CaInitCommand();
        if (caSession.getCAInfo(admin, CA_NAME) != null) {
            caSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }
    }

    public void tearDown() throws Exception {
    }
}
