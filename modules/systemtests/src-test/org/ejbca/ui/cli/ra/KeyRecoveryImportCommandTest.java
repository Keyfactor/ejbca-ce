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
package org.ejbca.ui.cli.ra;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** Testing the keyrecoveryimport CLI command, that a PKCS#12 keystore with existing (external) key recovery data (a private key and a certificate)
 * can be imported either for an existing end entity or creating a new end entity.
 * 
 * @version $Id$
 */
public class KeyRecoveryImportCommandTest {

    private static final String TESTCLASS_NAME = KeyRecoveryImportCommandTest.class.getSimpleName();
    private static final String END_ENTITY_SUBJECT_DN = "C=SE, O=PrimeKey, CN=" + TESTCLASS_NAME + "User";

    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private final KeyStoreCreateSessionRemote keyStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(TESTCLASS_NAME));
    private final KeyRecoveryImportCommand command = new KeyRecoveryImportCommand();

    private static X509CA x509ca = null;
    private static boolean wasKeyRecoveryEnabled = false;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME);
        final GlobalConfiguration configuration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        wasKeyRecoveryEnabled = configuration.getEnableKeyRecovery();
        configuration.setEnableKeyRecovery(true);
        globalConfigurationSession.saveConfiguration(authenticationToken, configuration);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        final GlobalConfiguration configuration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        configuration.setEnableKeyRecovery(wasKeyRecoveryEnabled);
        globalConfigurationSession.saveConfiguration(authenticationToken, configuration);
        if (x509ca != null) {
            CaTestUtils.removeCa(authenticationToken, x509ca.getCAInfo());
        }
    }

    /** Test to import key recovery data that already exists in the database, it should fail */
    @Test
    public void testImportAlreadyExisting() throws AuthorizationDeniedException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EndEntityProfileValidationException, WaitingForApprovalException, NotFoundException, EjbcaException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        final String username = TESTCLASS_NAME+"User";
        final EndEntityInformation userdata = new EndEntityInformation(username, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        final String password = "foo123";
        userdata.setPassword(password);
        try {
            endEntityManagementSession.addUser(authenticationToken, userdata, true);
            final byte[] userks = keyStoreSession.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, "prime256v1", AlgorithmConstants.KEYALGORITHM_EC);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(userks), password.toCharArray());
            final String alias = username;
            final Certificate certificate = keystore.getCertificate(alias);
            final PrivateKey privKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
            final KeyPair keys = new KeyPair(certificate.getPublicKey(), privKey);
            // Remove the generated certificate, so it is a "fresh" import with nothing in the database
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            assertTrue("Key recovery data should not already exists after generation", keyRecoverySession.addKeyRecoveryData(authenticationToken, EJBTools.wrap(certificate), TESTCLASS_NAME, EJBTools.wrap(keys)));
            final File temp = File.createTempFile("testImportAlreadyExisting", ".tmp");
            temp.deleteOnExit();
            try (FileOutputStream w = new FileOutputStream(temp)) {
                w.write(userks);            
            }
            // Try to add key recovery data to the existing end entity "username", this should not work as it already exists
            final String[] args = new String[] { "-f", temp.getAbsolutePath(), "--username", username, "--password", password };
            final CommandResult result = command.execute(args);
            assertEquals("Adding key recovery data should not work as it already exists", CommandResult.FUNCTIONAL_FAILURE.getReturnCode(), result.getReturnCode());
            // The certificate should not exist in the database after trying to import
            assertNull("Certificate should not exists in the database after failed import", certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(certificate)));
        } finally {
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            endEntityManagementSession.deleteUser(authenticationToken, username);
        }
    }

    /** Test to import key recovery data using a random username, where the certificate already exists in the database */
    @Test
    public void testImportRandomUserExistingCert() throws AuthorizationDeniedException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EndEntityProfileValidationException, WaitingForApprovalException, NotFoundException, EjbcaException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        final String username = TESTCLASS_NAME+"User";
        final EndEntityInformation userdata = new EndEntityInformation(username, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        final String password = "foo123";
        userdata.setPassword(password);
        Certificate certificate = null;
        try {
            endEntityManagementSession.addUser(authenticationToken, userdata, true);
            final byte[] userks = keyStoreSession.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, "prime256v1", AlgorithmConstants.KEYALGORITHM_EC);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(userks), password.toCharArray());
            final String alias = username;
            certificate = keystore.getCertificate(alias);
            assertFalse("Key recovery data should should not have been added by generate command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            final File temp = File.createTempFile("testImportRandomUser", ".tmp");
            temp.deleteOnExit();
            try (FileOutputStream w = new FileOutputStream(temp)) {
                w.write(userks);            
            }
            // Try to add key recovery data to a new random user 
            final String[] args = new String[] { "-f", temp.getAbsolutePath(), "--password", password };
            final CommandResult result = command.execute(args);
            assertEquals("Adding key recovery data should work", CommandResult.SUCCESS.getReturnCode(), result.getReturnCode());
            // Check that the key recovery data was added
            assertTrue("Key recovery data should have been added by CLI command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
        } finally {
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            if (certificate != null) {
                keyRecoverySession.removeKeyRecoveryData(authenticationToken, EJBTools.wrap(certificate));
                internalCertificateStoreSession.removeCertificate(CertTools.getFingerprintAsString(certificate));
            }
            endEntityManagementSession.deleteUser(authenticationToken, username);
        }
    }

    /** Test to import key recovery data where the issuing CA does not exist. Key recovery data can not be stored then because there is no CA to encrypt the data */
    @Test
    public void testImportRandomUserWithoutCA() throws Exception {

        // A temporary CA the we will delete to try to import without CA
        X509CA temporaryca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME + "Temporary");

        final String username = TESTCLASS_NAME+"User";
        final EndEntityInformation userdata = new EndEntityInformation(username, END_ENTITY_SUBJECT_DN, temporaryca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        final String password = "foo123";
        userdata.setPassword(password);
        Certificate certificate = null;
        try {
            endEntityManagementSession.addUser(authenticationToken, userdata, true);
            final byte[] userks = keyStoreSession.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, "prime256v1", AlgorithmConstants.KEYALGORITHM_EC);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(userks), password.toCharArray());
            final String alias = username;
            certificate = keystore.getCertificate(alias);
            assertFalse("Key recovery data should should not have been added by generate command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            // Remove the generated certificate, so it is a "fresh" import with nothing in the database
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            // Now remove the CA so it does not exist when trying to import the keystore
            CaTestUtils.removeCa(authenticationToken, temporaryca.getCAInfo()); 
            
            final File temp = File.createTempFile("testImportRandomUser", ".tmp");
            temp.deleteOnExit();
            try (FileOutputStream w = new FileOutputStream(temp)) {
                w.write(userks);            
            }
            // Try to add key recovery data to a new random user 
            final String[] args = new String[] { "-f", temp.getAbsolutePath(), "--password", password };
            final CommandResult result = command.execute(args);
            assertEquals("Adding key recovery data should not work as the issuing CA does not exist", CommandResult.CLI_FAILURE.getReturnCode(), result.getReturnCode());
            // The certificate should not exist in the database after trying to import
            assertNull("Certificate should not exists in the database after failed import", certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(certificate)));
        } finally {
            CaTestUtils.removeCa(authenticationToken, temporaryca.getCAInfo()); // if something failed and it was not removed
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            if (certificate != null) {
                keyRecoverySession.removeKeyRecoveryData(authenticationToken, EJBTools.wrap(certificate));
                internalCertificateStoreSession.removeCertificate(CertTools.getFingerprintAsString(certificate));
            }
            endEntityManagementSession.deleteUser(authenticationToken, username);
        }
    }

    /** Test to import key recovery data using a random username, where the certificate does not already exists in the database */
    @Test
    public void testImportRandomUserNonExistingCert() throws AuthorizationDeniedException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EndEntityProfileValidationException, WaitingForApprovalException, NotFoundException, EjbcaException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        final String username = TESTCLASS_NAME+"User";
        final EndEntityInformation userdata = new EndEntityInformation(username, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        final String password = "foo123";
        userdata.setPassword(password);
        Certificate certificate = null;
        try {
            endEntityManagementSession.addUser(authenticationToken, userdata, true);
            final byte[] userks = keyStoreSession.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, "prime256v1", AlgorithmConstants.KEYALGORITHM_EC);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(userks), password.toCharArray());
            final String alias = username;
            certificate = keystore.getCertificate(alias);
            assertFalse("Key recovery data should should not have been added by generate command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            // Remove the certificate from the database so it will be imported
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            assertNull("Certificate should not exist after removing", certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(certificate)));
            final File temp = File.createTempFile("testImportRandomUserNonExistingCert", ".tmp");
            temp.deleteOnExit();
            try (FileOutputStream w = new FileOutputStream(temp)) {
                w.write(userks);            
            }
            // Try to add key recovery data to a new random user 
            final String[] args = new String[] { "-f", temp.getAbsolutePath(), "--password", password };
            final CommandResult result = command.execute(args);
            assertEquals("Adding key recovery data should work", CommandResult.SUCCESS.getReturnCode(), result.getReturnCode());
            // Check that the key recovery data was added
            assertTrue("Key recovery data should have been added by CLI command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            assertNotNull("Certificate should exist after importing", certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(certificate)));
        } finally {
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, username);
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            if (certificate != null) {
                keyRecoverySession.removeKeyRecoveryData(authenticationToken, EJBTools.wrap(certificate));
                internalCertificateStoreSession.removeCertificate(CertTools.getFingerprintAsString(certificate));
            }
            endEntityManagementSession.deleteUser(authenticationToken, username);
        }
    }

    /** Test to import key recovery data to an existing end entity, where the certificate already exists in the database */
    @Test
    public void testImportExistingUserWithCert() throws AuthorizationDeniedException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EndEntityProfileValidationException, WaitingForApprovalException, NotFoundException, EjbcaException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        final String username = TESTCLASS_NAME+"User";
        final EndEntityInformation userdata = new EndEntityInformation(username, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        final String password = "foo123";
        userdata.setPassword(password);
        String fingerprint = null;
        try {
            endEntityManagementSession.addUser(authenticationToken, userdata, true);
            final byte[] userks = keyStoreSession.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, "prime256v1", AlgorithmConstants.KEYALGORITHM_EC);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(userks), password.toCharArray());
            final String alias = username;
            final Certificate certificate = keystore.getCertificate(alias);
            fingerprint = CertTools.getFingerprintAsString(certificate);
            assertFalse("Key recovery data should should not have been added by generate command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            final File temp = File.createTempFile("testImportExistingUserWithCert", ".tmp");
            temp.deleteOnExit();
            try (FileOutputStream w = new FileOutputStream(temp)) {
                w.write(userks);            
            }
            // Try to add key recovery data to the existing end entity "username", this should work as it does not already exist
            final String[] args = new String[] { "-f", temp.getAbsolutePath(), "--username", username, "--password", password };
            final CommandResult result = command.execute(args);
            // Check that the key recovery data was added
            assertEquals("Adding key recovery data should work", CommandResult.SUCCESS.getReturnCode(), result.getReturnCode());
            assertTrue("Key recovery data should have been added by CLI command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
        } finally {
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, username);
            if (fingerprint != null) {
                internalCertificateStoreSession.removeCertificatesByUsername(username);
            }
            endEntityManagementSession.deleteUser(authenticationToken, username);
        }
    }

    /** Test to import key recovery data to an existing end entity, where the certificate does not already exists in the database */
    @Test
    public void testImportExistingUserWithoutCert() throws AuthorizationDeniedException, EndEntityExistsException, CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EndEntityProfileValidationException, WaitingForApprovalException, NotFoundException, EjbcaException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        final String username = TESTCLASS_NAME+"User";
        final EndEntityInformation userdata = new EndEntityInformation(username, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        final String password = "foo123";
        userdata.setPassword(password);
        String fingerprint = null;
        try {
            endEntityManagementSession.addUser(authenticationToken, userdata, true);
            final byte[] userks = keyStoreSession.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, "prime256v1", AlgorithmConstants.KEYALGORITHM_EC);
            final KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(userks), password.toCharArray());
            final String alias = username;
            final Certificate certificate = keystore.getCertificate(alias);
            fingerprint = CertTools.getFingerprintAsString(certificate);
            assertFalse("Key recovery data should should not have been added by generate command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            // Remove the certificate from the database so it will be imported
            internalCertificateStoreSession.removeCertificatesByUsername(username);
            assertNull("Certificate should not exist after removing", certificateStoreSession.getCertificateInfo(fingerprint));
            final File temp = File.createTempFile("testImportExistingUserWithoutCert", ".tmp");
            temp.deleteOnExit();
            try (FileOutputStream w = new FileOutputStream(temp)) {
                w.write(userks);            
            }
            // Try to add key recovery data to the existing end entity "username", this should work as it does not already exist
            final String[] args = new String[] { "-f", temp.getAbsolutePath(), "--username", username, "--password", password };
            CommandResult result = command.execute(args);
            // Check that the key recovery data was added
            assertEquals("Adding key recovery data should work", CommandResult.SUCCESS.getReturnCode(), result.getReturnCode());
            assertTrue("Key recovery data should have been added by CLI command", keyRecoverySession.existsKeys(EJBTools.wrap(certificate)));
            assertNotNull("Certificate should exist after importing", certificateStoreSession.getCertificateInfo(fingerprint));

            // Try to add again, should fail
            result = command.execute(args);
            // Check that the key recovery data was added
            assertEquals("Adding key recovery data twice should fail work", CommandResult.FUNCTIONAL_FAILURE.getReturnCode(), result.getReturnCode());
        } finally {
            keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, username);
            if (fingerprint != null) {
                internalCertificateStoreSession.removeCertificatesByUsername(username);
            }
            endEntityManagementSession.deleteUser(authenticationToken, username);
        }
    }

}
