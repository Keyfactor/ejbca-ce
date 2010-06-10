package org.ejbca.ui.cli.ca;

import java.rmi.RemoteException;

import junit.framework.TestCase;

import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.TestTools;

/**
 * System test class for CaInitCommandTest
 * 
 * @author mikek
 * 
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
    private Admin admin;
    private ICAAdminSessionRemote caAdminSession;

    /**
     * Test trivial happy path for execute, i.e, create an ordinary CA.
     * 
     * @throws Exception
     * @throws AuthorizationDeniedException
     */
    public void testExecuteHappyPath() throws AuthorizationDeniedException, Exception {
        try {
            caInitCommand.execute(HAPPY_PATH_ARGS);
            assertNotNull("Happy path CA was not created.", caAdminSession.getCAInfo(admin, CA_NAME));
        } finally {
            caAdminSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }

    }

    public void testExecuteWithRootCACertificateProfile() throws AuthorizationDeniedException, Exception {
        try {
            caInitCommand.execute(ROOT_CA_ARGS);
            assertNotNull("CA was not created using ROOTCA certificate profile.", caAdminSession.getCAInfo(admin, CA_NAME));
        } finally {
            caAdminSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }

    }

    public void testExecuteWithCustomCertificateProfile() throws CertificateProfileExistsException, RemoteException, ErrorAdminCommandException {

        if (TestTools.getCertificateStoreSession().getCertificateProfile(admin, CERTIFICATE_PROFILE_NAME) == null) {
            CertificateProfile certificateProfile = new CertificateProfile();
            TestTools.getCertificateStoreSession().addCertificateProfile(admin, CERTIFICATE_PROFILE_NAME, certificateProfile);
        }
        try {
            CertificateProfile apa = TestTools.getCertificateStoreSession().getCertificateProfile(admin, CERTIFICATE_PROFILE_NAME);
            caInitCommand.execute(CUSTOM_PROFILE_ARGS);
            assertNull("CA was created using created using non ROOTCA or SUBCS certificate profile.", caAdminSession.getCAInfo(admin, CA_NAME));
        } finally {
            TestTools.getCertificateStoreSession().removeCertificateProfile(admin, CERTIFICATE_PROFILE_NAME);
        }
    }

    public void setUp() throws Exception {
        admin = new Admin(Admin.TYPE_INTERNALUSER);

        caInitCommand = new CaInitCommand();

        caAdminSession = TestTools.getCAAdminSession();

        if (caAdminSession.getCAInfo(admin, CA_NAME) != null) {
            caAdminSession.removeCA(admin, caInitCommand.getCAInfo(CA_NAME).getCAId());
        }

    }

    public void tearDown() throws Exception {

    }

}
