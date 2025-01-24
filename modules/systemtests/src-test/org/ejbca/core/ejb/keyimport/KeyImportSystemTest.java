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

package org.ejbca.core.ejb.keyimport;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.certificate.DnComponents;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.KeyImportSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.cesecore.keys.keyimport.KeyImportRequestData;
import org.cesecore.keys.keyimport.KeyImportResponseData;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;

public class KeyImportSystemTest extends CaTestCase {

    private static final String TEST_USERNAME      = "KeyImportSystemTestUser";
    private static final String TEST_USER_PASSWORD = "foo123";
    private static final String TEST_EEP_NAME = "KeyImportSystemTestEEP";
    private static final String TEST_CP_NAME = "KeyImportSystemTestCP";

    // Adjust these to match your environment (test CA, certificate profile, etc.)
    private static final String TEST_CA_DN                = "CN=TEST";

    // Base64 encoded P12 with 3 keys and 3 certificates
    private static final String TEST_P12_BASE64 =
            "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";
    // Base64 encoded P12 with 1 key and 1 certificate
    private static final String TEST_P12_BASE64_SMALLER =
            "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";

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final KeyImportSessionRemote keyImportSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyImportSessionRemote.class);
    private static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private static final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);

    private AuthenticationToken authenticationToken;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        authenticationToken = new TestAlwaysAllowLocalAuthenticationToken("KeyImportSystemTest");

        CertificateProfile certProfile = new CertificateProfile();
        certProfile.setAvailableCAs(List.of(SecConst.ALLCAS));
        certificateProfileSession.addCertificateProfile(authenticationToken, TEST_CP_NAME, certProfile);

        EndEntityProfile eeProfile = new EndEntityProfile();
        eeProfile.addField(DnComponents.COMMONNAME);
        eeProfile.addField(DnComponents.ORGANIZATION);
        eeProfile.addField(DnComponents.ORGANIZATIONALUNIT);
        eeProfile.setAvailableCAs(List.of(SecConst.ALLCAS));
        int certProfileId = certificateProfileSession.getCertificateProfileId(TEST_CP_NAME);
        eeProfile.setAvailableCertificateProfileIds(List.of(certProfileId));
        endEntityProfileSession.addEndEntityProfile(authenticationToken, TEST_EEP_NAME, eeProfile);

        // If an old leftover user is around, try to delete it
        if (endEntityManagementSession.existsUser(TEST_USERNAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, TEST_USERNAME);
        }
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Clean up created end entity if needed
        if (endEntityManagementSession.existsUser(TEST_USERNAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, TEST_USERNAME);
        }
        if (endEntityProfileSession.getEndEntityProfile(TEST_EEP_NAME) != null) {
            endEntityProfileSession.removeEndEntityProfile(authenticationToken, TEST_EEP_NAME);
        }
        if (certificateProfileSession.getCertificateProfile(TEST_CP_NAME) != null) {
            certificateProfileSession.removeCertificateProfile(authenticationToken, TEST_CP_NAME);
        }
        internalCertStoreSession.removeCertificatesByUsername(TEST_USERNAME);
        keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, TEST_USERNAME);
    }

    @Test
    public void testImportSingleKey() throws Exception {
        try {
            // Verify that our test CA actually exists
            CAInfo testCA = caSession.getCAInfo(authenticationToken, getTestCAName());
            if (testCA == null) {
                throw new IllegalStateException("Test CA with DN '" + TEST_CA_DN + "' does not exist in the system!");
            }

            // Build the KeyImportRequestData
            KeyImportKeystoreData singleP12Data = new KeyImportKeystoreData();
            singleP12Data.setUsername(TEST_USERNAME);
            singleP12Data.setPassword(TEST_USER_PASSWORD);
            singleP12Data.setKeystore(TEST_P12_BASE64_SMALLER);

            List<KeyImportKeystoreData> keystoreDataList = new ArrayList<>();
            keystoreDataList.add(singleP12Data);

            KeyImportRequestData requestData = new KeyImportRequestData();
            requestData.setIssuerDn(TEST_CA_DN);
            requestData.setCertificateProfileName(TEST_CP_NAME);
            requestData.setEndEntityProfileName(TEST_EEP_NAME);
            requestData.setKeystores(keystoreDataList);

            // Call the method under test
            KeyImportResponseData responseData = null;
            try {
                responseData = keyImportSession.importKeys(authenticationToken, requestData);
            } catch (EjbcaException e) {
                throw new AssertionError("Key import operation failed unexpectedly: " + e.getMessage(), e);
            }

            // Verify results
            // The KeyImportResponseData should not be null
            assertNotNull("Expected a non-null KeyImportResponseData", responseData);

            // Check for any general error message
            if (responseData.getGeneralErrorMessage() != null) {
                throw new AssertionError("Key import reported a general error: " + responseData.getGeneralErrorMessage());
            }

            // Should have no failures if everything went right
            List<KeyImportFailure> failures = responseData.getFailures();
            assertNotNull("Expected a non-null list of failures (could be empty).", failures);

            assertTrue("Expected zero failures, but got: " + failures, failures.isEmpty());

            // Confirm that the end entity was created in the DB
            EndEntityInformation endEntity = endEntityAccessSession.findUser(authenticationToken, TEST_USERNAME);
            assertNotNull("Expected the end entity '" + TEST_USERNAME + "' to be created by importKeys(...).", endEntity);

            // Check that the certificate exists
            Collection<CertificateWrapper> certificates = certificateStoreSession.findCertificatesByUsername(TEST_USERNAME);
            assertEquals("Expected one certificate, but got: " + certificates.size(), 1, certificates.size());
            for (CertificateWrapper certificate : certificates) {
                assertTrue("Expected KeyRecoveryData to exist for certificate, but it didn't.", keyRecoverySession.existsKeys(certificate));
            }
        } finally {
            // Clean up
            internalCertStoreSession.removeCertificatesByUsername(TEST_USERNAME);
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, TEST_USERNAME);
        }
    }

    @Test
    public void testImportMultipleKeys() throws Exception {
        try {
            // Verify that our test CA actually exists
            CAInfo testCA = caSession.getCAInfo(authenticationToken, getTestCAName());
            if (testCA == null) {
                throw new IllegalStateException("Test CA with DN '" + TEST_CA_DN + "' does not exist in the system!");
            }

            // Build the KeyImportRequestData
            KeyImportKeystoreData singleP12Data = new KeyImportKeystoreData();
            singleP12Data.setUsername(TEST_USERNAME);
            singleP12Data.setPassword(TEST_USER_PASSWORD);
            singleP12Data.setKeystore(TEST_P12_BASE64);

            List<KeyImportKeystoreData> keystoreDataList = new ArrayList<>();
            keystoreDataList.add(singleP12Data);

            KeyImportRequestData requestData = new KeyImportRequestData();
            requestData.setIssuerDn(TEST_CA_DN);
            requestData.setCertificateProfileName(TEST_CP_NAME);
            requestData.setEndEntityProfileName(TEST_EEP_NAME);
            requestData.setKeystores(keystoreDataList);

            // Call the method under test
            KeyImportResponseData responseData = null;
            try {
                responseData = keyImportSession.importKeys(authenticationToken, requestData);
            } catch (EjbcaException e) {
                throw new AssertionError("Key import operation failed unexpectedly: " + e.getMessage(), e);
            }

            // Verify results
            // The KeyImportResponseData should not be null
            assertNotNull("Expected a non-null KeyImportResponseData", responseData);

            // Check for any general error message
            if (responseData.getGeneralErrorMessage() != null) {
                throw new AssertionError("Key import reported a general error: " + responseData.getGeneralErrorMessage());
            }

            // Should have no failures if everything went right
            List<KeyImportFailure> failures = responseData.getFailures();
            assertNotNull("Expected a non-null list of failures (could be empty).", failures);

            assertTrue("Expected zero failures, but got: " + failures, failures.isEmpty());

            // Confirm that the end entity was created in the DB
            EndEntityInformation endEntity = endEntityAccessSession.findUser(authenticationToken, TEST_USERNAME);
            assertNotNull("Expected the end entity '" + TEST_USERNAME + "' to be created by importKeys(...).", endEntity);

            // Check that the certificate exists
            Collection<CertificateWrapper> certificates = certificateStoreSession.findCertificatesByUsername(TEST_USERNAME);
            assertEquals("Expected three certificates, but got: " + certificates.size(), 3, certificates.size());
            for (CertificateWrapper certificate : certificates) {
                assertTrue("Expected KeyRecoveryData to exist for certificate, but it didn't.", keyRecoverySession.existsKeys(certificate));
            }
        } finally {
            // Clean up
            internalCertStoreSession.removeCertificatesByUsername(TEST_USERNAME);
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, TEST_USERNAME);
        }
    }


    @Test
    public void testImportSingleKeystoreWithNonExistingCertificateProfile() throws Exception {
        KeyImportRequestData requestData = new KeyImportRequestData();
        requestData.setIssuerDn(TEST_CA_DN);
        requestData.setCertificateProfileName("SomeNonExistentProfile");
        requestData.setEndEntityProfileName(TEST_EEP_NAME);
        requestData.setKeystores(Collections.emptyList()); // intentionally empty to cause an error

        KeyImportResponseData responseData = keyImportSession.importKeys(authenticationToken, requestData);

        // We expect a general error message or an exception.
        assertNotNull("Expected a KeyImportResponseData even when call fails", responseData);
        String generalError = responseData.getGeneralErrorMessage();
        assertNotNull("Expected a general error message due to invalid certificate profile", generalError);
    }

    @Test
    public void testImportSingleKeystoreWithNonExistingEndEntityProfile() throws Exception {
        KeyImportRequestData requestData = new KeyImportRequestData();
        requestData.setIssuerDn(TEST_CA_DN);
        requestData.setCertificateProfileName(TEST_CP_NAME);
        requestData.setEndEntityProfileName("NonExistingEndEntityProfile");
        requestData.setKeystores(Collections.emptyList()); // intentionally empty to cause an error

        KeyImportResponseData responseData = keyImportSession.importKeys(authenticationToken, requestData);

        // We expect a general error message or an exception.
        assertNotNull("Expected a KeyImportResponseData even when call fails", responseData);
        String generalError = responseData.getGeneralErrorMessage();
        assertNotNull("Expected a general error message due to invalid end entity profile", generalError);
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}
