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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Category;
import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.logging.log4j.message.SimpleMessage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;

/**
 * Unit tests for the CaImportProfilesCommand class.
 * <br/>
 * Check resources-test/readme.txt for files definition.
 */
public class CaImportProfilesCommandSystemTest {

    private static final Logger log = LogManager.getLogger(CaImportProfilesCommandSystemTest.class);
    
    /* Must be initialized somehow, otherwise the other test logger fails. */
    @Rule
    public TestLogAppenderResource testLog = new TestLogAppenderResource(log);
    
    @Rule
    public TestLogAppenderResource testLogCmd;
    
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();
    
    private static final String profileName = CaImportProfilesCommandSystemTest.class.getSimpleName() + "ExistingProfile";
    
    private static final String eepName = "TestEndEntityProfile";
    private static final int cpId = 345999;
    private static final String cpName = "TestCertificateProfile";
    private static final int caId = -71969407;
    private static final String caName = "MyDefaultCA";
    private static final String username = "tomcat-for-testing";

    private static CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class, "cesecore-ejb");
    private static CertificateProfileSessionRemote certificateProfileSession = JndiHelper.getRemoteSession(CertificateProfileSessionRemote.class, "cesecore-ejb");
    private static EndEntityProfileSessionRemote endEntityProfileSession = JndiHelper.getRemoteSession(EndEntityProfileSessionRemote.class, "ejbca-ejb");
    private static PublisherSessionRemote publisherSession = JndiHelper.getRemoteSession(PublisherSessionRemote.class, "ejbca-ejb");
    private static EndEntityManagementSessionRemote endEntityManagementSession = JndiHelper.getRemoteSession(EndEntityManagementSessionRemote.class, "ejbca-ejb");
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaImportProfilesCommandSystemTest"));

    private CaImportProfilesCommand caImportProfilesCommand;

    @Before
    public void setUp() throws AuthorizationDeniedException {
        caImportProfilesCommand = new CaImportProfilesCommand();
        testLogCmd = new TestLogAppenderResource(caImportProfilesCommand.getLogger());
    }

    @After
    public void tearDown() throws Exception {
        if (endEntityManagementSession.existsUser(username)) {
            endEntityManagementSession.deleteUser(admin, username);
        }
        if (endEntityProfileSession.getEndEntityProfile(eepName) != null) {
            endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        }
        if (endEntityProfileSession.getEndEntityProfile(profileName + "_EP") != null) {
            endEntityProfileSession.removeEndEntityProfile(admin, profileName + "_EP");
        }
        if (endEntityProfileSession.getEndEntityProfile(profileName) != null) {
            endEntityProfileSession.removeEndEntityProfile(admin, profileName);
        }
        if (certificateProfileSession.getCertificateProfile(profileName) != null) {
            certificateProfileSession.removeCertificateProfile(admin, profileName);
        }
        if (certificateProfileSession.getCertificateProfile(cpName) != null) {
            certificateProfileSession.removeCertificateProfile(admin, cpName);
        }
        if (caSession.existsCa(caName)) {
            caSession.removeCA(admin, caId);
        }
    }

    @Test
    public void testFailOnMissingDirectoryParameter() {
        // given
        final String[] params = new String[] {};
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.CLI_FAILURE, commandResult);
        
        // No more logging here.
        // Missing parameters are handled in org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler in keyfactor-commons-cli
        // 
        // ERROR: Incorrect parameter usage.
        // The following mandatory arguments are missing or poorly formed, use --help for more information:
        //      -d      Directory containing profiles.
    }

    @Test
    public void testFailOnNonExistingCAInput() throws AuthorizationDeniedException {
        // given
        final String caName = "IDon'tExist";
        final String[] params = new String[] { "-d", "some", "--caname", caName };
        assertEquals("CA must not exists before test.", caSession.getCAInfo(admin, caName), null);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("ERROR - CA '" + caName + "' does not exist.");
    }

    @Test
    public void testFailOnAuthorizationDeniedExceptionOnCAInput() throws Exception {
        // given
        final String[] params = new String[] { "-u", username, "--clipassword", "serverpwd", "-d", "some", "--caname", caName };
        
        createCa(caName);
        
        if (!endEntityManagementSession.existsUser(username)) {
            final int caId = caSession.getAuthorizedCaIds(admin).get(0);
            final EndEntityInformation endEntity = new EndEntityInformation(username, "C=SE,O=primekey,CN=" + username, caId, null, null, new EndEntityType(EndEntityTypes.ENDUSER), 1, 1, EndEntityConstants.TOKEN_SOFT_P12, null);
            endEntity.setPassword("foo123");            
            endEntityManagementSession.addUser(admin, endEntity, false);
        }
        
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.AUTHORIZATION_FAILURE, commandResult);
        // If the CA exists:
        // else
        // CA 'fantasy' does not exist. is logged.
        // TODO: Could be solved in a separate ticket. I would expect not to leak information about CA database to unauthorized users.
        assertLog("ERROR - CLI user not authorized to CA '" + caName  + "'.");
    }

    @Test
    public void testFailOnCannotRead() {
        // given
        final String[] params = new String[] { "-d", "some" };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("ERROR - 'some' cannot be read.");
    }

    @Test
    public void testFailOnFileInput() throws IOException {
        // given
        final File inputFile = temporaryFolder.newFile("InputFile.file");
        final String[] params = new String[] { "-d", inputFile.getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("ERROR - '" + inputFile.getAbsolutePath() + "' is not a directory.");
    }

    @Test
    public void testFailOnEmptyDirectoryInput() throws IOException {
        // given
        final File inputDir = temporaryFolder.newFolder("empty_folder");
        final String[] params = new String[] { "-d", inputDir.getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("ERROR - '" + inputDir.getAbsolutePath() + "' is empty.");
    }

    @Test
    public void testSkipFileInputBecauseOfName() throws IOException {
        // given
        final String fileName = "certprofile.txt";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("INFO - Skipped: '" + fileName + "'");
    }

    @Test
    public void testSkipFileInputBecauseOfCertProfileNamePattern() throws IOException {
        // given
        final String fileName = "certprofile_.a";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
        assertLog("INFO - Skipped: '" + fileName + "'");
    }

    @Test
    public void testSkipFileInputBecauseOfEntityProfileNamePattern() throws IOException {
        // given
        final String fileName = "entityprofile_.a";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
        assertLog("INFO - Skipped: '" + fileName + "'");
    }

    @Test
    public void testNotProcessFixedCertProfile() throws IOException {
        // given
        final String profileName = "ENDUSER";
        final String fileName = "certprofile_" + profileName + "-1.xml";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Not adding fixed certificate profile '" + profileName + "'.");
    }

    @Test
    public void testNotProcessFixedEntityProfile() throws IOException {
        // given
        final String profileName = "EMPTY";
        final String fileName = "entityprofile_" + profileName + "-1.xml";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Not adding fixed entity profile '" + profileName + "'.");
    }

    @Test
    public void testSkipCertProfileWithExistingName() throws IOException {
        // given
        final int profileId = 111;
        final String profileName = "CP";
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        assertEquals("Certificate profile ID does not match.", certificateProfileSession.getCertificateProfileId(profileName), 0);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - Certificate profile id '" + profileId + "' already exist in database. Adding with a new profile id instead.");
        assertLog("ERROR - Failed to parse profile XML in '" + temporaryFolder.getRoot().getAbsolutePath() + "/certprofile_CP-111.xml': input contained no data");
    }

    @Test
    public void testRemapCertProfileWithExistingId() throws Exception {
        // given
        final int profileId = 609758752;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_" + profileName + "-609758752.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        if (certificateProfileSession.getCertificateProfile(profileId) == null) {
            certificateProfileSession.addCertificateProfile(admin, profileId, cpName, new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
        }
        assertNotNull("Certificate profile with ID " + profileId + " is null.", certificateProfileSession.getCertificateProfile(profileId));
        assertNull("Certificate profile " + profileName + " is not null.", certificateProfileSession.getCertificateProfile(profileName));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - Certificate profile id '" + profileId + "' already exist in database. Adding with a new profile id instead.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '-1' to database.");
    }

    @Test
    public void testSkipEntityProfileWithExistingName() throws Exception {
        // given
        final int profileId = 112;
        final String profileName = CaImportProfilesCommandSystemTest.profileName + "_EP";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        
        if (endEntityProfileSession.getEndEntityProfile(profileName) == null) {
            endEntityProfileSession.addEndEntityProfile(admin, profileId, profileName, new EndEntityProfile(true));
        }
        assertNotNull("End entity profile must not be null.", endEntityProfileSession.getEndEntityProfile(profileName));
        
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Entity profile '" + profileName + "' already exist in database.");
    }

    @Test
    public void testRemapEntityProfileWithExistingId() throws Exception {
        // given
        final int profileId = 198381618;
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_" + profileName + "-198381618.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        
        if (endEntityProfileSession.getEndEntityProfile(profileId) == null) {
            endEntityProfileSession.addEndEntityProfile(admin, profileId, eepName, new EndEntityProfile(0));
        }
        
        assertNotNull("End entity profile with ID " + profileId + " is null.", endEntityProfileSession.getEndEntityProfile(profileId));
        assertNull("End entity profile " + profileName + " is not null.", endEntityProfileSession.getEndEntityProfile(profileName));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - Entity profileid '" + profileId + "' already exist in database. Using '" + endEntityProfileSession.getEndEntityProfileId(profileName) + "' instead.");
    }

    @Test
    public void testRemoveNonExistingCAsFromCertProfileWithoutCAInput() throws Exception {
        // given
        final int profileId = 609758752;
        final int caToRemove = 1020;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_" + profileName + "-609758752-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        
        assertFalse("CA to remove " + caToRemove + " must not exist.", caSession.existsCa(caToRemove));
        
        if (certificateProfileSession.getCertificateProfileId(profileName) != 0) {
            certificateProfileSession.removeCertificateProfile(admin, profileName);
        }
        assertTrue("Certificate profile " + profileName + " must not exist.", certificateProfileSession.getCertificateProfileId(profileName) == 0);
        
        if (certificateProfileSession.getCertificateProfile(profileId) != null) { 
            certificateProfileSession.removeCertificateProfile(admin, certificateProfileSession.getCertificateProfileName(profileId));
        }
        assertNull("Certificate profile " + profileId + " must not exist.", certificateProfileSession.getCertificateProfile(profileId));
        
        final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.setAvailableCAs(List.of(1020));
        certificateProfileSession.addCertificateProfile(admin, cpId, cpName, cp);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - CA with id " + caToRemove + " was not found and will not be used in certificate profile '" + profileName + "'.");
        assertLog("ERROR - No CAs left in certificate profile '" + profileName + "' and no CA specified on command line. Using ANYCA.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database.");
    }

    @Test
    public void testRemoveNonExistingCAsFromCertProfileWithCAInput() throws Exception {
        // given
        final int profileId = 609758752;
        final int caToRemove = 1020;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_" + profileName + "-609758752-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath(), "--caname", caName };
        
        createCa(caName);
        
        assertNull("CAInfo for CA with ID " + caToRemove + " must be null", caSession.getCAInfo(admin, caToRemove));
        assertFalse("CA to remove " + caToRemove + " must not exist.", caSession.existsCa(caToRemove));
        
        if (certificateProfileSession.getCertificateProfileId(profileName) != 0) {
            certificateProfileSession.removeCertificateProfile(admin, profileName);
        }
        assertTrue("Certificate profile " + profileName + " must not exist.", certificateProfileSession.getCertificateProfileId(profileName) == 0);
        
        if (certificateProfileSession.getCertificateProfile(profileId) != null) { 
            certificateProfileSession.removeCertificateProfile(admin, certificateProfileSession.getCertificateProfileName(profileId));
        }
        assertNull("Certificate profile " + profileId + " must not exist.", certificateProfileSession.getCertificateProfile(profileId));
        
        final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        cp.setAvailableCAs(List.of(1020));
        certificateProfileSession.addCertificateProfile(admin, cpId, cpName, cp);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - CA with id " + caToRemove + " was not found and will not be used in certificate profile '" + profileName + "'.");
        assertLog("WARN - No CAs left in certificate profile '" + profileName + "'. Using CA supplied on command line with id '" + caId + "'.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database.");
    }

    @Test
    public void testRemoveUnknownPublishersFromCertProfile() throws Exception {
        // given
        final int profileId = 609758752;
        final int publisherToRemove = 1120;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_" + profileName + "-609758752-Publisher.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        assertNull("Certificate profile " + profileName + " is not null.", certificateProfileSession.getCertificateProfile(profileName));
        assertNull("Certificate profile with ID " + profileId + " is not null.", certificateProfileSession.getCertificateProfile(profileId));
        assertNull("Publisher with ID " + publisherToRemove + " is not null.", publisherSession.getPublisher(publisherToRemove));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - Publisher with id " + publisherToRemove + " was not found and will not be used in certificate profile '" + profileName + "'.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database.");
    }

    @Test
    public void testRemoveUnknownCertificateProfileForEntityProfile() throws Exception {
        // given
        final int profileId = 198381618;
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_" + profileName + "-198381618-CertProfile.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        assertNull("End entity profile " + profileName + " is not null.", endEntityProfileSession.getEndEntityProfile(profileName));
        assertNull("End entity profile with ID " + profileId + " is not null.", endEntityProfileSession.getEndEntityProfile(profileId));
        assertNull("Certificate profile with ID " + profileId + " is not null.", certificateProfileSession.getCertificateProfile(profileId));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - End Entity Profile '" + profileName + "' references certificate profile 609758752 that does not exist.");
        assertLog("WARN - End Entity Profile '" + profileName + "' only references certificate profile(s) that does not exist. Using ENDUSER profile.");
        assertLog("INFO - Added entity profile '" + profileName + "' to database.");
    }

    @Test
    public void testRemoveNonExistingCAsFromEntityProfileWithoutCAInput() throws Exception {
        // given
        final int profileId = 198381618;
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_" + profileName + "-198381618-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        assertFalse("CA with ID " + -1027462528 + " is not null.", caSession.existsCa(-1027462528));
        assertNull("Certificate profile with ID " + cpId + " is not null.", certificateProfileSession.getCertificateProfile(cpId));
        certificateProfileSession.addCertificateProfile(admin, cpId, cpName, new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
        assertNull("End entity profile " + profileName + " is not null.", endEntityProfileSession.getEndEntityProfile(profileName));
        assertNull("End entity profile with ID " + profileId + " is not null.", endEntityProfileSession.getEndEntityProfile(profileId));
        // endEntityProfileSession.addEndEntityProfile(adminToken, profileId, profileName, new EndEntityProfile(true));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - CA with id -1027462528 was not found and will not be used in end entity profile '" + profileName + "'.");
        assertLog("ERROR - No CAs left in end entity profile '" + profileName + "' and no CA specified on command line. Using ALLCAs.");
        assertLog("WARN - Changing default CA in end entity profile '" + profileName + "' to 1.");
        assertLog("INFO - Added entity profile '" + profileName + "' to database.");
    }

    @Test
    public void testRemoveNonExistingCAsFromEntityProfileWithCAInput() throws Exception {
        // given
        final int profileId = 198381618;
        final int caToRemove = -1027462528;
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_" + profileName + "-198381618-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath(), "--caname", caName };
        
        createCa(caName);
        assertNull("CAInfo for CA with ID " + caToRemove + " must be null", caSession.getCAInfo(admin, caToRemove));
        
        assertNull("Certificate profile with ID " + cpId + " is not null.", certificateProfileSession.getCertificateProfile(cpId));
        certificateProfileSession.addCertificateProfile(admin, cpId, cpName, new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
        assertNull("End entity profile " + profileName + " is not null.", endEntityProfileSession.getEndEntityProfile(profileName));
        assertNull("End entity profile with ID " + profileId + " is not null.", endEntityProfileSession.getEndEntityProfile(profileId));
        
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Importing certificate and end entity profiles: ");
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - CA with id " + caToRemove + " was not found and will not be used in end entity profile '" + profileName + "'.");
        assertLog("WARN - No CAs left in end entity profile '" + profileName + "'. Using CA supplied on command line with id '" + caId + "'.");
        assertLog("WARN - Changing default CA in end entity profile '" + profileName + "' to " + caId + ".");
        assertLog("INFO - Added entity profile '" + profileName + "' to database.");
    }
    
    private void createCa(final String name) throws Exception {
        final X509CA ca = CaTestUtils.createTestX509CA("CN=" + name, "foo123".toCharArray(), false);
        ca.setName(name);
        caSession.addCA(admin, ca);
        assertNotNull("CAInfo for CA " + name + " must not be null", caSession.getCAInfo(admin, name));
    }
    
    private void assertLog(final String logString) {
        final List<String> logMessages = testLogCmd.getAppender().getMessages();
        if (!logMessages.contains(logString)) {
            final String errorMessage = "Event log is missing: " + logString;
            log.error(errorMessage);
            for (final String logMessage : logMessages) {
                log.error("log(n): " + logMessage);
            }
            fail(errorMessage);
        }
    }
    
    // Uses log4j compatibility mode. Do not reuse.
    
    static class TestLogAppenderResource extends ExternalResource {

        private static final String APPENDER_NAME = "log4jRuleAppender";
        private static final Layout LAYOUT = new PatternLayout("%-4r [%t] %-5p %c %x - %m%n");

        private final Logger logger;
        
        private static TestAppender appender = new TestAppender(); 

        public TestLogAppenderResource(final Logger logger) {
            this.logger = logger;
            logger.setLevel(Level.DEBUG);
        }

        @Override
        protected void before() {
            appender.setName(APPENDER_NAME);
            appender.setLayout(LAYOUT);
            appender.setThreshold(Level.DEBUG);
            // Add the Appender to the root logger
            Category cat = logger;
            while (cat.getParent() != null) {
                cat.setAdditivity(true); // pass log entries to parent also
                cat = cat.getParent();
            }
            cat.addAppender(appender);
            appender.clear();
        }

        @Override
        protected void after() {
            logger.removeAppender(APPENDER_NAME);
        }

        public TestAppender getAppender() {
            return appender;
        }
        
    }

    static class TestAppender extends AppenderSkeleton {
        
        private final List<LoggingEvent> events = new ArrayList<>();
        private final List<String> messages = new ArrayList<>();

        @Override
        public boolean requiresLayout() {
            return false;
        }

        @Override
        protected void append(final LoggingEvent loggingEvent) {
            final String logMessage = loggingEvent.getLevel() + " - " + ((SimpleMessage) loggingEvent.getMessage()).getFormattedMessage();
            messages.add(logMessage);
            events.add(loggingEvent);
        }

        @Override
        public void close() {
        }

        public List<String> getMessages() {
            return new ArrayList<>(messages);
        }

        public void clear() {
            events.clear();
            messages.clear();
        }
    }
}
