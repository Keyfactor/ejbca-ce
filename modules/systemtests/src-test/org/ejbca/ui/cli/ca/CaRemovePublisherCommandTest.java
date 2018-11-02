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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CA RemovePublisher command
 * 
 * @version $Id$
 */
public class CaRemovePublisherCommandTest {

    private static final String PUBLISHER_NAME = "1428removepublisher";
    private static final String CA_NAME = "1428removepublisher";
    private static final String CERT_PROFILE_NAME = "1428removepublisher";
    private static final String[] HAPPY_PATH_REMOVE_ARGS = { PUBLISHER_NAME };    
    private static final String[] NON_EXISTING_REMOVE_ARGS = { PUBLISHER_NAME+"foo" };    
    private static final String[] HAPPY_PATH_LISTREF_ARGS = { PUBLISHER_NAME, "--listref" };
    private static final String[] HAPPY_PATH_REMOVEREF_ARGS = { PUBLISHER_NAME, "--removeref" };
    private static final String[] HAPPY_PATH_REMOVEALL_ARGS = { PUBLISHER_NAME, "--removeall" };
    private static final String[] INVALID_ARGS = { PUBLISHER_NAME, "--foo" };

    private CaRemovePublisherCommand command;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaRemovePublisherCommandTest"));

    private PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote profileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        command = new CaRemovePublisherCommand();
        try {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
        try {
            profileSession.removeCertificateProfile(admin, CERT_PROFILE_NAME);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.createTestCA(CA_NAME);
    }
    
    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        CaTestCase.removeTestCA(CA_NAME);
    }

    @Test
    public void testExecuteRemoveWithNoRefs() throws PublisherExistsException, AuthorizationDeniedException {
        LdapPublisher publisher = new LdapPublisher();
        publisherProxySession.addPublisher(admin, PUBLISHER_NAME, publisher);
        try {
            LdapPublisher pub1 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNotNull("Publisher should have been added", pub1);
            // Call CLI with invalid args
            CommandResult result = command.execute(INVALID_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.CLI_FAILURE, result);
            // Try to remove a publisher that does not exist
            result = command.execute(NON_EXISTING_REMOVE_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.FUNCTIONAL_FAILURE, result);
            // Try to remove one that does exist
            result = command.execute(HAPPY_PATH_REMOVE_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we removed
            LdapPublisher pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNull("Publisher should have been removed", pub2);            
        } finally {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
        }
    }

    @Test
    public void testExecuteRemoveWithRefs() throws PublisherExistsException, AuthorizationDeniedException, CADoesntExistsException, CertificateProfileExistsException {
        try {
            LdapPublisher publisher = new LdapPublisher();
            int id = publisherProxySession.addPublisher(admin, PUBLISHER_NAME, publisher);
            LdapPublisher pub1 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNotNull("Publisher should have been added", pub1);            
            // Add a reference to a CA
            CAInfo info = caSession.getCAInfo(admin, CA_NAME);
            ArrayList<Integer> pubs = new ArrayList<Integer>();
            pubs.add(id);
            info.setCRLPublishers(pubs);
            caSession.editCA(admin, info);
            // Add a reference to a certificate profile
            CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            profile.setPublisherList(pubs);
            int profileId = profileSession.addCertificateProfile(admin, CERT_PROFILE_NAME, profile);

            // That was the pre-requisites, now work on removal
            // Just removing should not work, since there are references.
            CommandResult result = command.execute(HAPPY_PATH_REMOVE_ARGS);
            assertEquals("Command was not sucessfully run, it should have given an error trying to remove publisher with references.", CommandResult.FUNCTIONAL_FAILURE, result);
            // Check that we didn't remove
            LdapPublisher pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNotNull("Publisher should not have been removed", pub2);            
            
            // List references command, should not remove anything
            result = command.execute(HAPPY_PATH_LISTREF_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we didn't remove
            pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNotNull("Publisher should not have been removed", pub2);
            CertificateProfile profile1 = profileSession.getCertificateProfile(profileId);
            assertEquals("Profile should still contain reference to publisher.", 1, profile1.getPublisherList().size());
            CAInfo info1 = caSession.getCAInfo(admin, CA_NAME);
            assertEquals("CA should still contain reference to publisher.", 1, info1.getCRLPublishers().size());
            
            // Remove references, should remove references but not publisher
            result = command.execute(HAPPY_PATH_REMOVEREF_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we didn't remove publisher, but did remove references to it
            pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNotNull("Publisher should not have been removed", pub2);
            CertificateProfile profile2 = profileSession.getCertificateProfile(profileId);
            assertEquals("Profile should not contain reference to publisher.", 0, profile2.getPublisherList().size());
            CAInfo info2 = caSession.getCAInfo(admin, CA_NAME);
            assertEquals("CA should not contain reference to publisher.", 0, info2.getCRLPublishers().size());
            
            // Remove now, should remove publisher that does not have references
            result = command.execute(HAPPY_PATH_REMOVE_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we removed
            pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNull("Publisher should have been removed", pub2);            
            
            // Remove all should remove references and publisher
            // First, add back publisher and references
            publisher = new LdapPublisher();
            id = publisherProxySession.addPublisher(admin, PUBLISHER_NAME, publisher);
            pub1 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNotNull("Publisher should have been added", pub1);            
            pubs = new ArrayList<Integer>();
            pubs.add(id);
            info = caSession.getCAInfo(admin, CA_NAME);
            info.setCRLPublishers(pubs);
            caSession.editCA(admin, info);
            profile = profileSession.getCertificateProfile(profileId);
            profile.setPublisherList(pubs);
            profileSession.changeCertificateProfile(admin, CERT_PROFILE_NAME, profile);
            // This should not work
            result = command.execute(HAPPY_PATH_REMOVE_ARGS);
            assertEquals("Command was not sucessfully run, it should have given an error trying to remove publisher with references.", CommandResult.FUNCTIONAL_FAILURE, result);
            // Run to remove all
            result = command.execute(HAPPY_PATH_REMOVEALL_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we removed
            pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertNull("Publisher should have been removed", pub2);            
            profile2 = profileSession.getCertificateProfile(profileId);
            assertEquals("Profile should not contain reference to publisher.", 0, profile2.getPublisherList().size());
            info2 = caSession.getCAInfo(admin, CA_NAME);
            assertEquals("CA should not contain reference to publisher.", 0, info2.getCRLPublishers().size());

        } finally {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
            profileSession.removeCertificateProfile(admin, CERT_PROFILE_NAME);
        }
    }


}
