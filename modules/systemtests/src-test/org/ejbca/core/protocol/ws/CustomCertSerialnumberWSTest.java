package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test requires that "Enable End Entity Profile Limitations" in syste configuration is turned of.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CustomCertSerialnumberWSTest extends CommonEjbcaWS {

    private static final Logger log = Logger.getLogger(CustomCertSerialnumberWSTest.class);

    private final String wsadminRoleName = "WsCustomSernoTestRole";
    
	private static final String END_ENTITY_PROFILE = "customSerialNrCertEndEntityProfile";

	private static final String CERTIFICATE_PROFILE = "customSerialNrCertProfile";

	private static final String TEST_USER1 = "customSerialNrUser1";

	private static final String TEST_USER2 = "customSerialNrUser2";

	private static final String TEST_USER3 = "customSerialNrUser3";

    private InternalCertificateStoreSessionRemote sernoHelperSession= EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @BeforeClass
    public static void setupAccessRights() {
    	adminBeforeClass();
    }

    @Before
    public void setUpAdmin() throws Exception {
		adminSetUpAdmin();
    }

    @Override
	@After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void test00setupAccessRights() throws Exception {
        super.setupAccessRights(this.wsadminRoleName);
    }

    @Test
    public void test01CreateCertWithCustomSN() throws Exception {

        log.debug(">test01CreateCertWithCustomSN");

        try {            
            final BigInteger serno = SernoGeneratorRandom.instance().getSerno();
            log.debug("serno: " + serno);

            if (this.certificateProfileSession.getCertificateProfileId(CERTIFICATE_PROFILE) != 0) {
                this.certificateProfileSession.removeCertificateProfile(intAdmin, CERTIFICATE_PROFILE);
            }
            final int certProfID; {
                final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                profile.setAllowCertSerialNumberOverride(true);
                this.certificateProfileSession.addCertificateProfile(intAdmin, CERTIFICATE_PROFILE, profile);
                certProfID = this.certificateProfileSession.getCertificateProfileId(CERTIFICATE_PROFILE);
            }
            if ( this.endEntityProfileSession.getEndEntityProfile(END_ENTITY_PROFILE)!=null ) {
                this.endEntityProfileSession.removeEndEntityProfile(intAdmin, END_ENTITY_PROFILE);
            }
            {
                final EndEntityProfile profile = new EndEntityProfile(true);
                profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certProfID));
                this.endEntityProfileSession.addEndEntityProfile(intAdmin, END_ENTITY_PROFILE, profile);
            }
            // Creating certificate for user: wsfoo
            UserDataVOWS user = new UserDataVOWS(TEST_USER1, PASSWORD, true, "C=SE, CN="+TEST_USER1,
                    getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
                    UserDataVOWS.TOKEN_TYPE_P12, END_ENTITY_PROFILE, CERTIFICATE_PROFILE, null);
            user.setCertificateSerialNumber(serno);

            try {
                // Make sure EJBCA thinks that we don't have a unique serno index, then we should get a CustomCertSerialNumberException
                sernoHelperSession.setUniqueSernoIndexFalse();
                this.ejbcaraws.softTokenRequest(user, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                fail("We should not be able to create a certificate with customCertSerialNo when there is no unique issuerDN/certSerno index in the database.");
            } catch (Exception e) {
                assertTrue("Exception message should tell that custom cert serial is not allowed: "+e.getMessage(), e.getMessage().contains("Custom certificate serial number not allowed since there is no unique index on (issuerDN,serialNumber) on the 'CertificateData' table."));
            }
            // Make sure EJBCA "thinks" that we have a unique serno index in the database
            sernoHelperSession.setUniqueSernoIndexTrue();

            KeyStore ksenv = this.ejbcaraws.softTokenRequest(user, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
            java.security.KeyStore keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);
            assertNotNull(keyStore);
            Enumeration<String> en = keyStore.aliases();
            String alias = en.nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            assertTrue("wsfoo serno: " + cert.getSerialNumber(), cert.getSerialNumber().compareTo(serno) == 0);

            // Creating certificate for user: wsfoo2
            user = new UserDataVOWS(TEST_USER2, PASSWORD, true, "C=SE, CN="+TEST_USER2,
                    getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
                    UserDataVOWS.TOKEN_TYPE_P12, END_ENTITY_PROFILE, CERTIFICATE_PROFILE, null);

            ksenv = this.ejbcaraws.softTokenRequest(user,null,"1024", AlgorithmConstants.KEYALGORITHM_RSA);
            keyStore = KeyStoreHelper.getKeyStore(ksenv.getKeystoreData(), "PKCS12", PASSWORD);
            assertNotNull(keyStore);
            en = keyStore.aliases();
            alias = en.nextElement();
            cert = (X509Certificate) keyStore.getCertificate(alias);
            log.debug("wsfoo2 serno: " + cert.getSerialNumber());
            assertTrue(cert.getSerialNumber().compareTo(serno) != 0);

            // Creating certificate for user: wsfoo3
            user = new UserDataVOWS(TEST_USER3, PASSWORD, true, "C=SE, CN="+TEST_USER3,
                    getAdminCAName(), null, "foo@anatom.se", UserDataVOWS.STATUS_NEW,
                    UserDataVOWS.TOKEN_TYPE_P12, END_ENTITY_PROFILE, CERTIFICATE_PROFILE, null);
            user.setCertificateSerialNumber(serno);

            // See if we really have a unique serno index in the database
            sernoHelperSession.resetUniqueSernoCheck();
            boolean hasUniqueSernoIndex = sernoHelperSession.existsUniqueSernoIndex();
            if (hasUniqueSernoIndex) {
                ksenv = null;
                try {
                    ksenv = this.ejbcaraws.softTokenRequest(user, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                } catch (Exception e) {
                    final String message = e.getMessage();
                    log.debug("Message when there is already a certificate in the DB: "+message);
                    assertTrue("Unexpected Exception." ,
                            message.startsWith("There is already a certificate stored in 'CertificateData' with the serial number") ||
                            message.startsWith("Transaction rolled back"));
                }
                assertNull(ksenv);            
            } else {
                log.info("We don't have a unique serno index, se we skipped trying to generate the same cert again to prove it can not be stored in database.");                
            }
        } finally {
            // Reset so that EJBCA "knows" if it has a unique index in the database or not
            sernoHelperSession.resetUniqueSernoCheck();
        }

        log.debug("<test01CreateCertWithCustomSN");
    }
    @Test
    public void test99cleanUpAdmins() throws Exception {
		try {
			this.certificateProfileSession.removeCertificateProfile(intAdmin, CERTIFICATE_PROFILE);
		} catch (AuthorizationDeniedException e) {} // NOPMD: do nothing
		try {
			this.endEntityProfileSession.removeEndEntityProfile(intAdmin, END_ENTITY_PROFILE);
        } catch (AuthorizationDeniedException e) {} // NOPMD: do nothing
		try {
            this.endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_USER1, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {} // NOPMD: do nothing
		try {
            this.endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_USER2, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {} // NOPMD: do nothing
		try {
            this.endEntityManagementSession.revokeAndDeleteUser(intAdmin, TEST_USER3, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
        } catch (Exception e) {} // NOPMD: do nothing
		try {
	        super.cleanUpAdmins(this.wsadminRoleName);
        } catch (Exception e) {} // NOPMD: do nothing
    }

    @Override
	public String getRoleName() {
        return this.wsadminRoleName+"Mgmt";
    }
}
