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

import java.util.ArrayList;
import java.util.Collections;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaMsCompatibilityIrreversibleException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

import static org.ejbca.ui.cli.infrastructure.command.CommandResult.SUCCESS;
import static org.ejbca.ui.cli.infrastructure.command.CommandResult.FUNCTIONAL_FAILURE;
import static org.ejbca.ui.cli.infrastructure.command.CommandResult.CLI_FAILURE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * System test class for CA RemovePublisher command
 *
 * @version $Id$
 */
public class CaRemovePublisherCommandSystemTest {

    private static final String PUBLISHER_NAME = "1428removepublisher";
    private static final String CA_NAME = "1428removepublisher";
    private static final String CERT_PROFILE_NAME = "1428removepublisher";
    private static final String[] HAPPY_PATH_REMOVE_ARGS = { PUBLISHER_NAME };
    private static final String[] NON_EXISTING_REMOVE_ARGS = { PUBLISHER_NAME + "foo" };
    private static final String[] HAPPY_PATH_LISTREF_ARGS = { PUBLISHER_NAME, "--listref" };
    private static final String[] HAPPY_PATH_REMOVEREF_ARGS = { PUBLISHER_NAME, "--removeref" };
    private static final String[] HAPPY_PATH_REMOVEALL_ARGS = { PUBLISHER_NAME, "--removeall" };
    private static final String[] INVALID_ARGS = { PUBLISHER_NAME, "--foo" };

    private CaRemovePublisherCommand command;
    private static final AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaRemovePublisherCommandTest"));

    private static final PublisherSessionRemote PUBLISHER_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private static final PublisherProxySessionRemote PUBLISHER_PROXY_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(
            PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CaSessionRemote CA_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CertificateProfileSessionRemote CERTIFICATE_PROFILE_SESSION = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    private int ldapPublisherId;
    private int certificateProfileId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CaTestCase.createTestCA(CA_NAME);
    }

    @Before
    public void setUp() throws Exception {
        command = new CaRemovePublisherCommand();
        // Add LdapPublisher
        ldapPublisherId = PUBLISHER_PROXY_SESSION.addPublisher(ADMIN, PUBLISHER_NAME, new LdapPublisher());
    }

    @After
    public void tearDown() {
        removePublisherAndCertificateProfile();
        // flush cache
        PUBLISHER_PROXY_SESSION.flushPublisherCache();
    }

    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        CaTestCase.removeTestCA(CA_NAME);
    }

    // Call CLI with invalid args
    @Test
    public void failOnInvalidArguments() {
        // given
        // when
        final CommandResult result = command.execute(INVALID_ARGS);
        assertEquals("CLI return code mismatch.", CLI_FAILURE, result);
    }

    // Try to remove a publisher that does not exist
    @Test
    public void failOnRemovalOfNonExisting() {
        // given
        // when
        final CommandResult result = command.execute(NON_EXISTING_REMOVE_ARGS);
        // then
        assertEquals("CLI return code mismatch.", FUNCTIONAL_FAILURE, result);
    }

    @Test
    public void successOnRemovalWithNoRefs() {
        // given
        assertLdapPublisherExists();
        // when
        // Try to remove
        final CommandResult result = command.execute(HAPPY_PATH_REMOVE_ARGS);
        // then
        assertEquals("CLI return code mismatch.", SUCCESS, result);
        // Check that we removed
        assertLdapPublisherDoesNotExist();
    }

    @Test
    public void failOnRemovalWithRefs() throws Exception {
        // given
        assertLdapPublisherExists();
        addPublisherIdToCa();
        addPublisherIdToCertificateProfile();
        // when
        // Just removing should not work, since there are references.
        final CommandResult result = command.execute(HAPPY_PATH_REMOVE_ARGS);
        // then
        assertEquals("CLI return code mismatch. It should have given an error trying to remove publisher with references.", FUNCTIONAL_FAILURE, result);
        // Check that we didn't remove
        assertLdapPublisherExists();
    }

    @Test
    public void successOnListReferences() throws Exception {
        // given
        assertLdapPublisherExists();
        addPublisherIdToCa();
        addPublisherIdToCertificateProfile();
        // when
        // List references command, should not remove anything
        final CommandResult result = command.execute(HAPPY_PATH_LISTREF_ARGS);
        // then
        assertEquals("CLI return code mismatch.", SUCCESS, result);
        // Check that we didn't remove
        assertLdapPublisherExists();
        assertCertificateProfileReferenceExists();
        assertCAReferenceExists();
    }

    @Test
    public void successOnReferencesRemoval() throws Exception {
        // given
        assertLdapPublisherExists();
        addPublisherIdToCa();
        addPublisherIdToCertificateProfile();
        // when
        // Remove references, should remove references but not publisher
        final CommandResult result = command.execute(HAPPY_PATH_REMOVEREF_ARGS);
        assertEquals("CLI return code mismatch.", SUCCESS, result);
        // Check that we didn't remove publisher, but did remove references to it
        assertLdapPublisherExists();
        assertCertificateProfileReferenceDoesNotExist();
        assertCAReferenceDoesNotExist();
    }

    @Test
    public void successOnRemovalAfterReferencesRemoval() throws Exception {
        // given
        assertLdapPublisherExists();
        addPublisherIdToCa();
        addPublisherIdToCertificateProfile();
        // when
        // Remove now, should remove publisher that does not have references
        final CommandResult result1 = command.execute(HAPPY_PATH_REMOVEREF_ARGS);
        final CommandResult result2 = command.execute(HAPPY_PATH_REMOVE_ARGS);
        // then
        assertEquals("CLI return code mismatch.", SUCCESS, result1);
        assertEquals("CLI return code mismatch.", SUCCESS, result2);
        // Check that we removed
        assertCertificateProfileReferenceDoesNotExist();
        assertCAReferenceDoesNotExist();
        assertLdapPublisherDoesNotExist();
    }

    @Test
    public void successOnRemoveAllWithReferences() throws Exception {
        // given
        assertLdapPublisherExists();
        addPublisherIdToCa();
        addPublisherIdToCertificateProfile();
        // Remove all should remove references and publisher
        final CommandResult result = command.execute(HAPPY_PATH_REMOVEALL_ARGS);
        assertEquals("CLI return code mismatch.", SUCCESS, result);
        // Check that we removed
        assertCertificateProfileReferenceDoesNotExist();
        assertCAReferenceDoesNotExist();
        assertLdapPublisherDoesNotExist();
    }

    // Removes publisher and certificate profile by name, remove publishers from CA
    private void removePublisherAndCertificateProfile() {
        try {
            PUBLISHER_PROXY_SESSION.removePublisherInternal(ADMIN, PUBLISHER_NAME);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
        try {
            CERTIFICATE_PROFILE_SESSION.removeCertificateProfile(ADMIN, CERT_PROFILE_NAME);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
        try {
            final CAInfo caInfo = CA_SESSION.getCAInfo(ADMIN, CA_NAME);
            caInfo.setCRLPublishers(new ArrayList<>());
            CA_SESSION.editCA(ADMIN, caInfo);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
    }

    private void addPublisherIdToCa() throws AuthorizationDeniedException, InternalKeyBindingNonceConflictException, CADoesntExistsException, CaMsCompatibilityIrreversibleException {
        // Add a reference to a CA
        final CAInfo caInfo = CA_SESSION.getCAInfo(ADMIN, CA_NAME);
        caInfo.setCRLPublishers(new ArrayList<>(Collections.singletonList(ldapPublisherId)));
        CA_SESSION.editCA(ADMIN, caInfo);
    }

    private void addPublisherIdToCertificateProfile() throws CertificateProfileExistsException, AuthorizationDeniedException {
        // Add a reference to a certificate profile
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setPublisherList(new ArrayList<>(Collections.singletonList(ldapPublisherId)));
        certificateProfileId = CERTIFICATE_PROFILE_SESSION.addCertificateProfile(ADMIN, CERT_PROFILE_NAME, certificateProfile);
    }

    private LdapPublisher getLdapPublisherByName(final String publisherName) {
        return (LdapPublisher) PUBLISHER_SESSION.getPublisher(publisherName);
    }

    private void assertLdapPublisherExists() {
        assertNotNull("LdapPublisher should exist", getLdapPublisherByName(PUBLISHER_NAME));
    }

    private void assertLdapPublisherDoesNotExist() {
        assertNull("LdapPublisher should not exist", getLdapPublisherByName(PUBLISHER_NAME));
    }

    private CertificateProfile getCertificateProfileById(final int certificateProfileId) {
        return CERTIFICATE_PROFILE_SESSION.getCertificateProfile(certificateProfileId);
    }

    private void assertCertificateProfileReferenceExists() {
        assertEquals("CertificateProfile should contain a reference to the publisher.", 1, getCertificateProfileById(certificateProfileId).getPublisherList().size());
    }

    private void assertCertificateProfileReferenceDoesNotExist() {
        assertEquals("CertificateProfile should not contain a reference to the publisher.", 0, getCertificateProfileById(certificateProfileId).getPublisherList().size());
    }

    private CAInfo getCAInfo(final String caName) throws AuthorizationDeniedException {
        return CA_SESSION.getCAInfo(ADMIN, caName);
    }

    private void assertCAReferenceExists() throws AuthorizationDeniedException {
        assertEquals("CA should contain a reference to the publisher.", 1, getCAInfo(CA_NAME).getCRLPublishers().size());
    }

    private void assertCAReferenceDoesNotExist() throws AuthorizationDeniedException {
        assertEquals("CA should not contain a reference to the publisher.", 0, getCAInfo(CA_NAME).getCRLPublishers().size());
    }
}
