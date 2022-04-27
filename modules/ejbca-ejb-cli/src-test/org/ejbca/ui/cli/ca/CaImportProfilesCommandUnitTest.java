package org.ejbca.ui.cli.ca;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderSessionRemote;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.cli.TestFileResource;
import org.ejbca.ui.cli.TestLogAppenderResource;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.easymock.EasyMock.anyInt;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the CaImportProfilesCommand class.
 * <br/>
 * Check resources-test/readme.txt for files definition.
 *
 * @version $Id$
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({JndiHelper.class})
@PowerMockIgnore(value = {"com.sun.org.apache.xerces.*" })
public class CaImportProfilesCommandUnitTest {

    @Rule
    public TestLogAppenderResource testLog = new TestLogAppenderResource(Logger.getLogger(CaImportProfilesCommand.class));
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();


    private static CaSessionRemote caSessionRemoteMock = createMock(CaSessionRemote.class);
    private static CertificateProfileSessionRemote certificateProfileSessionMock = createMock(CertificateProfileSessionRemote.class);
    private static CliAuthenticationProviderSessionRemote cliAuthenticationProviderSessionMock = createMock(CliAuthenticationProviderSessionRemote.class);
    private static CliAuthenticationToken cliAuthenticationToken = createMock(CliAuthenticationToken.class);
    private static EndEntityProfileSessionRemote endEntityProfileSessionMock = createMock(EndEntityProfileSessionRemote.class);
    private static PublisherSessionRemote publisherSessionMock = createMock(PublisherSessionRemote.class);

    private CaImportProfilesCommand caImportProfilesCommand;

    @Before
    public void setUp() {
        // Init mocks
        PowerMock.mockStatic(JndiHelper.class);
        // Setup mocks' calls
        expect(JndiHelper.getRemoteSession(CaSessionRemote.class, "cesecore-ejb")).andReturn(caSessionRemoteMock);
        expect(JndiHelper.getRemoteSession(CertificateProfileSessionRemote.class, "cesecore-ejb")).andReturn(certificateProfileSessionMock);
        expect(JndiHelper.getRemoteSession(CliAuthenticationProviderSessionRemote.class, "ejbca-ejb")).andReturn(cliAuthenticationProviderSessionMock);
        expect(JndiHelper.getRemoteSession(EndEntityProfileSessionRemote.class, "ejbca-ejb")).andReturn(endEntityProfileSessionMock);
        expect(JndiHelper.getRemoteSession(PublisherSessionRemote.class, "ejbca-ejb")).andReturn(publisherSessionMock);
        expect(cliAuthenticationProviderSessionMock.authenticate(anyObject(AuthenticationSubject.class))).andReturn(cliAuthenticationToken).anyTimes();
        // Replay mocks
        PowerMock.replay(JndiHelper.class);
        replay(cliAuthenticationProviderSessionMock);
        //
        caImportProfilesCommand = new CaImportProfilesCommand();
    }

    @After
    public void tearDown() {
        // Reset static mock
        reset(caSessionRemoteMock);
        reset(certificateProfileSessionMock);
        reset(cliAuthenticationProviderSessionMock);
        reset(endEntityProfileSessionMock);
        reset(publisherSessionMock);
    }

    @Test
    public void shouldFailOnMissingDirectoryParameter() {
        // given
        final ParameterContainer parameterContainer = new ParameterContainer();
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.CLI_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Directory parameter is mandatory."));
    }

    @Test
    public void shouldFailOnNonExistingCAInput() throws AuthorizationDeniedException {
        // given
        final String caName = "IDon'tExist";
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", "some", true);
        parameterContainer.put("--caname", caName, true);
        expect(caSessionRemoteMock.getCAInfo(cliAuthenticationToken, caName)).andReturn(null);
        replay(caSessionRemoteMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - CA '" + caName + "' does not exist."));
        verify(caSessionRemoteMock);
    }

    @Test
    public void shouldFailOnAuthorizationDeniedExceptionOnCAInput() throws AuthorizationDeniedException {
        // given
        final String caName = "IDon'tHaveAccess";
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", "some", true);
        parameterContainer.put("--caname", caName, true);
        expect(caSessionRemoteMock.getCAInfo(cliAuthenticationToken, caName)).andThrow(new AuthorizationDeniedException());
        replay(caSessionRemoteMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.AUTHORIZATION_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - CLI user not authorized to CA '" + caName  + "'."));
        verify(caSessionRemoteMock);
    }

    @Test
    public void shouldFailOnCannotRead() {
        // given
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", "some", true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - 'some' cannot be read."));
    }

    @Test
    public void shouldFailOnFileInput() throws IOException {
        // given
        final File inputFile = temporaryFolder.newFile("InputFile.file");
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", inputFile.getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - '" + inputFile.getAbsolutePath() + "' is not a directory."));
    }

    @Test
    public void shouldFailOnEmptyDirectoryInput() throws IOException {
        // given
        final File inputDir = temporaryFolder.newFolder("empty_folder");
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", inputDir.getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - '" + inputDir.getAbsolutePath() + "' is empty."));
    }

    @Test
    public void shouldSkipFileInputBecauseOfName() throws IOException {
        // given
        final String fileName = "certprofile.txt";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Skipped: '" + fileName + "'"));
    }

    @Test
    public void shouldSkipFileInputBecauseOfCertProfileNamePattern() throws IOException {
        // given
        final String fileName = "certprofile_.a";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Filename not as expected (cert/entityprofile_<name>-<id>.xml)."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Skipped: '" + fileName + "'"));
    }

    @Test
    public void shouldSkipFileInputBecauseOfEntityProfileNamePattern() throws IOException {
        // given
        final String fileName = "entityprofile_.a";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Filename not as expected (cert/entityprofile_<name>-<id>.xml)."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Skipped: '" + fileName + "'"));
    }

    @Test
    public void shouldNotProcessFixedCertProfile() throws IOException {
        // given
        final String profileName = "ENDUSER";
        final String fileName = "certprofile_" + profileName + "-1.xml";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Not adding fixed certificate profile '" + profileName + "'."));
    }

    @Test
    public void shouldNotProcessFixedEntityProfile() throws IOException {
        // given
        final String profileName = "EMPTY";
        final String fileName = "entityprofile_" + profileName + "-1.xml";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Not adding fixed entity profile '" + profileName + "'."));
    }

    @Test
    public void shouldSkipCertProfileWithExistingName() throws IOException {
        // given
        final int profileId = 111;
        final String profileName = "CP";
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(certificateProfileSessionMock.getCertificateProfileId(profileName)).andReturn(1);
        replay(certificateProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Certificate profile '" + profileName + "' already exist in database."));
        verify(certificateProfileSessionMock);
    }

    @Test
    public void shouldRemapCertProfileWithExistingId() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(certificateProfileSessionMock.getCertificateProfileId(profileName)).andReturn(0).times(2);
        expect(certificateProfileSessionMock.getCertificateProfile(profileId)).andReturn(createMock(CertificateProfile.class));
        expect(certificateProfileSessionMock.addCertificateProfile(anyObject(), anyString(), anyObject())).andReturn(0);
        replay(certificateProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - Certificate profile id '" + profileId + "' already exist in database. Adding with a new profile id instead."));
        verify(certificateProfileSessionMock);
    }

    @Test
    public void shouldSkipEntityProfileWithExistingName() throws IOException {
        // given
        final int profileId = 112;
        final String profileName = "EP";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        temporaryFolder.newFile(fileName);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileName)).andReturn(createMock(EndEntityProfile.class));
        replay(endEntityProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.FUNCTIONAL_FAILURE, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - Entity profile '" + profileName + "' already exist in database."));
        verify(endEntityProfileSessionMock);
    }

    @Test
    public void shouldRemapEntityProfileWithExistingId() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 198381618;
        final int freeEndEntityProfileId = 113;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(certificateProfileSessionMock.getCertificateProfile(anyInt())).andReturn(createMock(CertificateProfile.class));
        replay(certificateProfileSessionMock);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileName)).andReturn(null);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileId)).andReturn(createMock(EndEntityProfile.class));
        expect(endEntityProfileSessionMock.findFreeEndEntityProfileId()).andReturn(freeEndEntityProfileId);
        endEntityProfileSessionMock.addEndEntityProfile(anyObject(), anyInt(), anyString(), anyObject());
        expectLastCall().andVoid();
        replay(endEntityProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - Entity profileid '" + profileId + "' already exist in database. Using '" + freeEndEntityProfileId + "' instead."));
        verify(certificateProfileSessionMock);
        verify(endEntityProfileSessionMock);
    }

    @Test
    public void shouldRemoveNonExistingCAsFromCertProfileWithoutCAInput() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int caToRemove = 1020;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(caSessionRemoteMock.existsCa(caToRemove)).andReturn(false);
        replay(caSessionRemoteMock);
        expect(certificateProfileSessionMock.getCertificateProfileId(profileName)).andReturn(0).times(2);
        expect(certificateProfileSessionMock.getCertificateProfile(profileId)).andReturn(null);
        expect(certificateProfileSessionMock.addCertificateProfile(anyObject(), anyInt(), anyString(), anyObject())).andReturn(0);
        replay(certificateProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - CA with id " + caToRemove + " was not found and will not be used in certificate profile '" + profileName + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - No CAs left in certificate profile '" + profileName + "' and no CA specified on command line. Using ANYCA."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database."));
        verify(caSessionRemoteMock);
        verify(certificateProfileSessionMock);
    }

    @Test
    public void shouldRemoveNonExistingCAsFromCertProfileWithCAInput() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int caId = 77;
        final String caName = "MyDefaultCA";
        final CAInfo caInfo = createMock(CAInfo.class);
        final int caToRemove = 1020;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        parameterContainer.put("--caname", caName, true);
        expect(caInfo.getCAId()).andReturn(caId);
        replay(caInfo);
        expect(caSessionRemoteMock.getCAInfo(cliAuthenticationToken, caName)).andReturn(caInfo);
        expect(caSessionRemoteMock.existsCa(caToRemove)).andReturn(false);
        replay(caSessionRemoteMock);
        expect(certificateProfileSessionMock.getCertificateProfileId(profileName)).andReturn(0).times(2);
        expect(certificateProfileSessionMock.getCertificateProfile(profileId)).andReturn(null);
        expect(certificateProfileSessionMock.addCertificateProfile(anyObject(), anyInt(), anyString(), anyObject())).andReturn(0);
        replay(certificateProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - CA with id " + caToRemove + " was not found and will not be used in certificate profile '" + profileName + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - No CAs left in certificate profile '" + profileName + "'. Using CA supplied on command line with id '" + caId + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database."));
        verify(caSessionRemoteMock);
        verify(certificateProfileSessionMock);
    }

    @Test
    public void shouldRemoveUnknownPublishersFromCertProfile() throws IOException, CertificateProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 609758752;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int publisherToRemove = 1120;
        final String fileName = "certprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("certprofiles/certprofile_CaImportProfilesCommandUnitTest-609758752-Publisher.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(certificateProfileSessionMock.getCertificateProfileId(profileName)).andReturn(0).times(2);
        expect(certificateProfileSessionMock.getCertificateProfile(profileId)).andReturn(null);
        expect(certificateProfileSessionMock.addCertificateProfile(anyObject(), anyInt(), anyString(), anyObject())).andReturn(0);
        replay(certificateProfileSessionMock);
        expect(publisherSessionMock.getPublisher(publisherToRemove)).andReturn(null);
        replay(publisherSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - Publisher with id " + publisherToRemove + " was not found and will not be used in certificate profile '" + profileName + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Added certificate profile '" + profileName + "', '" + profileId + "' to database."));
        verify(certificateProfileSessionMock);
        verify(publisherSessionMock);
    }

    @Test
    public void shouldRemoveUnknownCertificateProfileForEntityProfile() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 198381618;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618-CertProfile.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(certificateProfileSessionMock.getCertificateProfile(anyInt())).andReturn(null);
        replay(certificateProfileSessionMock);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileName)).andReturn(null);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileId)).andReturn(null);
        endEntityProfileSessionMock.addEndEntityProfile(anyObject(), anyInt(), anyString(), anyObject());
        expectLastCall().andVoid();
        replay(endEntityProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - End Entity Profile '" + profileName + "' references certificate profile 609758752 that does not exist."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - End Entity Profile '" + profileName + "' only references certificate profile(s) that does not exist. Using ENDUSER profile."));
        verify(certificateProfileSessionMock);
        verify(endEntityProfileSessionMock);
    }

    @Test
    public void shouldRemoveNonExistingCAsFromEntityProfileWithoutCAInput() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 198381618;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        expect(caSessionRemoteMock.existsCa(anyInt())).andReturn(false);
        replay(caSessionRemoteMock);
        expect(certificateProfileSessionMock.getCertificateProfile(anyInt())).andReturn(createMock(CertificateProfile.class));
        replay(certificateProfileSessionMock);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileName)).andReturn(null);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileId)).andReturn(null);
        endEntityProfileSessionMock.addEndEntityProfile(anyObject(), anyInt(), anyString(), anyObject());
        expectLastCall().andVoid();
        replay(endEntityProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - CA with id -1027462528 was not found and will not be used in end entity profile '" + profileName + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("ERROR - No CAs left in end entity profile '" + profileName + "' and no CA specified on command line. Using ALLCAs."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - Changing default CA in end entity profile '" + profileName + "' to 1."));
        verify(caSessionRemoteMock);
        verify(certificateProfileSessionMock);
        verify(endEntityProfileSessionMock);
    }

    @Test
    public void shouldRemoveNonExistingCAsFromEntityProfileWithCAInput() throws IOException, EndEntityProfileExistsException, AuthorizationDeniedException {
        // given
        final int profileId = 198381618;
        final String profileName = "CaImportProfilesCommandUnitTest";
        final int caId = 77;
        final String caName = "MyDefaultCA";
        final CAInfo caInfo = createMock(CAInfo.class);
        final int caToRemove = -1027462528;
        final String fileName = "entityprofile_" + profileName + "-" + profileId + ".xml";
        final File inputFile = temporaryFolder.newFile(fileName);
        final TestFileResource testFile = new TestFileResource("entityprofiles/entityprofile_CaImportProfilesCommandUnitTest-198381618-CA.xml");
        FileUtils.copyFile(testFile.getFile(), inputFile);
        final ParameterContainer parameterContainer = new ParameterContainer();
        parameterContainer.put("-d", temporaryFolder.getRoot().getAbsolutePath(), true);
        parameterContainer.put("--caname", caName, true);
        expect(caInfo.getCAId()).andReturn(caId);
        replay(caInfo);
        expect(caSessionRemoteMock.getCAInfo(cliAuthenticationToken, caName)).andReturn(caInfo);
        expect(caSessionRemoteMock.existsCa(caToRemove)).andReturn(false);
        replay(caSessionRemoteMock);
        expect(certificateProfileSessionMock.getCertificateProfile(anyInt())).andReturn(createMock(CertificateProfile.class));
        replay(certificateProfileSessionMock);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileName)).andReturn(null);
        expect(endEntityProfileSessionMock.getEndEntityProfile(profileId)).andReturn(null);
        endEntityProfileSessionMock.addEndEntityProfile(anyObject(), anyInt(), anyString(), anyObject());
        expectLastCall().andVoid();
        replay(endEntityProfileSessionMock);
        // when
        final CommandResult commandResult = caImportProfilesCommand.execute(parameterContainer);
        // then
        assertEquals("CLI return code mismatch.", CommandResult.SUCCESS, commandResult);
        // ECA-10510 Requires fix for Appender / LogEvent (CommandBase.getLogger())
        // assertTrue("Event log is missing.", testLog.getOutput().contains("INFO - Filename: '" + fileName + "'"));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - CA with id " + caToRemove + " was not found and will not be used in end entity profile '" + profileName + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - No CAs left in end entity profile 'CaImportProfilesCommandUnitTest'. Using CA supplied on command line with id '" + caId + "'."));
        // assertTrue("Event log is missing.", testLog.getOutput().contains("WARN - Changing default CA in end entity profile '" + profileName + "' to " + caId + "."));
        verify(caSessionRemoteMock);
        verify(certificateProfileSessionMock);
        verify(endEntityProfileSessionMock);
    }
}
