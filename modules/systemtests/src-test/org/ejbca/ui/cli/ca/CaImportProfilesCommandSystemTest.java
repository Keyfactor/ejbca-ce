package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExternalResource;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Unit tests for the CaImportProfilesCommand class.
 * <br/>
 * Check resources-test/readme.txt for files definition.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CaImportProfilesCommandSystemTest {

    private static final Logger log = LogManager.getLogger(CaImportProfilesCommandSystemTest.class);
    
    @Rule
    public TestLogAppenderResource testLog = new TestLogAppenderResource(log);
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();
    
    private static final String eepName = "TestEndEntityProfile";
    private static final int cpId = 345999;
    private static final String cpName = "TestCertificateProfile";
    private static final int caId = -71969407;
    private static final String caName = "MyDefaultCA";

    private static CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class, "cesecore-ejb");
    private static CertificateProfileSessionRemote certificateProfileSession = JndiHelper.getRemoteSession(CertificateProfileSessionRemote.class, "cesecore-ejb");
    private static EndEntityProfileSessionRemote endEntityProfileSession = JndiHelper.getRemoteSession(EndEntityProfileSessionRemote.class, "ejbca-ejb");
    private static PublisherSessionRemote publisherSession = JndiHelper.getRemoteSession(PublisherSessionRemote.class, "ejbca-ejb");

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaImportProfilesCommandSystemTest"));

    private CaImportProfilesCommand caImportProfilesCommand;

    @Before
    public void setUp() throws AuthorizationDeniedException {
        caImportProfilesCommand = new CaImportProfilesCommand();
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        if (endEntityProfileSession.getEndEntityProfile(eepName) != null) {
            endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        }
        if (endEntityProfileSession.getEndEntityProfile("EP") != null) {
            endEntityProfileSession.removeEndEntityProfile(admin, "EP");
        }
        if (endEntityProfileSession.getEndEntityProfile("CaImportProfilesCommandUnitTest") != null) {
            endEntityProfileSession.removeEndEntityProfile(admin, "CaImportProfilesCommandUnitTest");
        }
        if (certificateProfileSession.getCertificateProfile("CaImportProfilesCommandUnitTest") != null) {
            certificateProfileSession.removeCertificateProfile(admin, "CaImportProfilesCommandUnitTest");
        }
        if (certificateProfileSession.getCertificateProfile(cpName) != null) {
            certificateProfileSession.removeCertificateProfile(admin, cpName);
        }
        if (caSession.existsCa(caName)) {
            caSession.removeCA(admin, caId);
        }
    }

    @Test
    public void test_01_shouldFailOnMissingDirectoryParameter() {
        // given
        final String[] params = new String[] {};
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.CLI_FAILURE, commandResult);
        assertLog("ERROR - Directory parameter is mandatory.");
    }

    @Test
    public void test_02_shouldFailOnNonExistingCAInput() throws AuthorizationDeniedException {
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
    public void test_03_shouldFailOnAuthorizationDeniedExceptionOnCAInput() throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, AuthorizationDeniedException, CAExistsException {
        // given
        final String[] params = new String[] { "-u", "tomcat", "--clipassword", "serverpwd", "-d", "some", "--caname", caName };
        
        createCa(caName);
        
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.AUTHORIZATION_FAILURE, commandResult);
        assertLog("ERROR - CLI user not authorized to CA '" + caName  + "'.");
    }

    @Test
    public void test_04_shouldFailOnCannotRead() {
        // given
        final String[] params = new String[] { "-d", "some" };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("ERROR - 'some' cannot be read.");
    }

    @Test
    public void test_05_shouldFailOnFileInput() throws IOException {
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
    public void test_06_shouldFailOnEmptyDirectoryInput() throws IOException {
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
    public void test_07_shouldSkipFileInputBecauseOfName() throws IOException {
        // given
        final String fileName = "certprofile.txt";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("INFO - Skipped: '" + fileName + "'");
    }

    @Test
    public void test_08_shouldSkipFileInputBecauseOfCertProfileNamePattern() throws IOException {
        // given
        final String fileName = "certprofile_.a";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
        assertLog("INFO - Skipped: '" + fileName + "'");
    }

    @Test
    public void test_09_shouldSkipFileInputBecauseOfEntityProfileNamePattern() throws IOException {
        // given
        final String fileName = "entityprofile_.a";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
        assertLog("INFO - Skipped: '" + fileName + "'");
    }

    @Test
    public void test_10_shouldNotProcessFixedCertProfile() throws IOException {
        // given
        final String profileName = "ENDUSER";
        final String fileName = "certprofile_" + profileName + "-1.xml";
        temporaryFolder.newFile(fileName);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Not adding fixed certificate profile '" + profileName + "'.");
    }

    @Test
    public void test_11_shouldNotProcessFixedEntityProfile() throws IOException {
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
    public void test_12_shouldSkipCertProfileWithExistingName() throws IOException {
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
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Certificate profile '" + profileName + "' already exist in database.");
    }

    @Test
    public void test_13_shouldRemapCertProfileWithExistingId() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752.xml");
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
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - Certificate profile id '" + profileId + "' already exist in database. Adding with a new profile id instead.");
    }

    @Test
    public void test_14_shouldSkipEntityProfileWithExistingName() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 112;
        final String profileName = "EP";
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
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("ERROR - Entity profile '" + profileName + "' already exist in database.");
    }

    @Test
    public void test_15_shouldRemapEntityProfileWithExistingId() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 198381618;
        final int freeEndEntityProfileId = 113;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618.xml");
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
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - Entity profileid '" + profileId + "' already exist in database. Using '" + freeEndEntityProfileId + "' instead.");
    }

    @Test
    public void test_16_shouldRemoveNonExistingCAsFromCertProfileWithoutCAInput() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int caToRemove = 1020;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752-CA.xml");
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
        assertLog("WARN - CA with id " + caToRemove + " was not found and will not be used in certificate profile '" + profileName + "'.");
        assertLog("ERROR - No CAs left in certificate profile '" + profileName + "' and no CA specified on command line. Using ANYCA.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database.");
    }

    @Test
    public void test_17_shouldRemoveNonExistingCAsFromCertProfileWithCAInput() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException, CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, CAExistsException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int caToRemove = 1020;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752-CA.xml");
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
        assertLog("WARN - CA with id " + caToRemove + " was not found and will not be used in certificate profile '" + profileName + "'.");
        assertLog("WARN - No CAs left in certificate profile '" + profileName + "'. Using CA supplied on command line with id '" + caId + "'.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database.");
    }

    @Test
    public void test_18_shouldRemoveUnknownPublishersFromCertProfile() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int publisherToRemove = 1120;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752-Publisher.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        assertNull("Certificate profile " + profileName + " is not null.", certificateProfileSession.getCertificateProfile(profileName));
        assertNull("Certificate profile with ID " + profileId + " is not null.", certificateProfileSession.getCertificateProfile(profileId));
        assertNull("Publisher with ID " + publisherToRemove + " is not null.", publisherSession.getPublisher(publisherToRemove));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("WARN - Publisher with id " + publisherToRemove + " was not found and will not be used in certificate profile '" + profileName + "'.");
        assertLog("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database.");
    }

    @Test
    public void test_19_shouldRemoveUnknownCertificateProfileForEntityProfile() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 198381618;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618-CertProfile.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final String[] params = new String[] { "-d", temporaryFolder.getRoot().getAbsolutePath() };
        assertNull("End entity profile " + profileName + " is not null.", endEntityProfileSession.getEndEntityProfile(profileName));
        assertNull("End entity profile with ID " + profileId + " is not null.", endEntityProfileSession.getEndEntityProfile(profileId));
        assertNull("Certificate profile with ID " + profileId + " is not null.", certificateProfileSession.getCertificateProfile(profileId));
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(params);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - End Entity Profile '" + profileName + "' references certificate profile 609758752 that does not exist.");
        assertLog("WARN - End Entity Profile '" + profileName + "' only references certificate profile(s) that does not exist. Using ENDUSER profile.");
    }

    @Test
    public void test_20_shouldRemoveNonExistingCAsFromEntityProfileWithoutCAInput() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException, CertificateProfileExistsException {
        // given
        final int profileId = 198381618;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618-CA.xml");
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
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - CA with id -1027462528 was not found and will not be used in end entity profile '" + profileName + "'.");
        assertLog("ERROR - No CAs left in end entity profile '" + profileName + "' and no CA specified on command line. Using ALLCAs.");
        assertLog("WARN - Changing default CA in end entity profile '" + profileName + "' to 1.");
    }

    @Test
    public void test_21_shouldRemoveNonExistingCAsFromEntityProfileWithCAInput() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException, CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, CAExistsException, CertificateProfileExistsException {
        // given
        final int profileId = 198381618;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int caToRemove = -1027462528;
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618-CA.xml");
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
        assertLog("INFO - Filename: '" + fileName + "'");
        assertLog("WARN - CA with id " + caToRemove + " was not found and will not be used in end entity profile '" + profileName + "'.");
        assertLog("WARN - No CAs left in end entity profile 'CaImportProfilesCommandUnitTest'. Using CA supplied on command line with id '" + caId + "'.");
        assertLog("WARN - Changing default CA in end entity profile '" + profileName + "' to " + caId + ".");
    }
    
    private void createCa(final String name) throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, CAExistsException, AuthorizationDeniedException {
        final X509CA ca = CaTestUtils.createTestX509CA("CN=" + name, "foo123".toCharArray(), false);
        ca.setName(name);
        caSession.addCA(admin, ca);
        assertNotNull("CAInfo for CA " + name + " must not be null", caSession.getCAInfo(admin, name));
    }
    
    private void assertLog(final String logString) {
        final List<String> logMessages = testLog.getAppender().getMessages();
        if (!logMessages.contains(logString)) {
            final String errorMessage = "Event log is missing: " + logString;
            log.error(errorMessage);
            for (final String logMessage : logMessages) {
                log.error("log: " + logMessage);
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
