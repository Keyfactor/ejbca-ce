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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CA EditPublisher command
 * 
 * @version $Id$
 */
public class CaEditPublisherCommandTest {

    private static final String PUBLISHER_NAME = "1327publisher2";
    private static final String GCP_PUBLISHER_NAME = "1327GCPpublisher3";
    private static final String[] HAPPY_PATH_ARGS = { PUBLISHER_NAME, "hostnames", "myhost.com" };
    private static final String[] HAPPY_PATH_GCP_ARGS = { GCP_PUBLISHER_NAME, "propertyData", "primekey http://www.primekey.se" };
    private static final String[] HAPPY_PATH_WITH_TYPE_ARGS = { PUBLISHER_NAME, "addMultipleCertificates", "true" };
    private static final String[] HAPPY_PATH_GETVALUE_ARGS = { PUBLISHER_NAME, "-getValue", "addMultipleCertificates" };
    private static final String[] HAPPY_PATH_LISTFIELDS_ARGS = { PUBLISHER_NAME, "-listFields" };
    private static final String[] MISSING_ARGS = { PUBLISHER_NAME };
    private static final String[] INVALID_FIELD_ARGS = { PUBLISHER_NAME, "hostname", "myhost.com" };

    private CaEditPublisherCommand command;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaEditPublisherCommandTest"));

    private PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    @Before
    public void setUp() throws Exception {
        command = new CaEditPublisherCommand();
        try {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
        } catch (Exception e) {
            // NOPMD: Ignore.
        }
    }

    @Test
    public void testExecuteHappyPath() throws PublisherExistsException, AuthorizationDeniedException {
        LdapPublisher publisher = new LdapPublisher();
        publisher.setHostnames("myhost1");
        publisherProxySession.addPublisher(admin, PUBLISHER_NAME, publisher);
        try {
            LdapPublisher pub1 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertEquals("Hostnames was not added as it should", "myhost1", pub1.getHostnames());
            CommandResult result = command.execute(HAPPY_PATH_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we edited
            LdapPublisher pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertEquals("Hostnames was not changed as it should", "myhost.com", pub2.getHostnames());
            result = command.execute(HAPPY_PATH_WITH_TYPE_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we edited
            pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertEquals("AddMultipleCertificates was not changed as it should", true, pub2.getAddMultipleCertificates());

            // Try to get value and list fields without exceptions...
            result = command.execute(HAPPY_PATH_GETVALUE_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            result = command.execute(HAPPY_PATH_LISTFIELDS_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
        } finally {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
        }
        // Try a custom publisher as well
        try {
            CustomPublisherContainer gcp = new CustomPublisherContainer();
            gcp.setClassPath(GeneralPurposeCustomPublisher.class.getName());
            gcp.setPropertyData("foo=bar");
            publisherProxySession.addPublisher(admin, GCP_PUBLISHER_NAME, gcp);
            CustomPublisherContainer pub1 = (CustomPublisherContainer) publisherSession.getPublisher(GCP_PUBLISHER_NAME);
            assertEquals("Propertydata was not added as it should", "foo=bar", pub1.getPropertyData());
            CommandResult result = command.execute(HAPPY_PATH_GCP_ARGS);
            assertEquals("Command was not sucessfully run.", CommandResult.SUCCESS, result);
            // Check that we edited
            CustomPublisherContainer pub2 = (CustomPublisherContainer) publisherSession.getPublisher(GCP_PUBLISHER_NAME);
            assertEquals("Propertydata was not changed as it should", "primekey http://www.primekey.se", pub2.getPropertyData());
        } finally {
            publisherProxySession.removePublisherInternal(admin, GCP_PUBLISHER_NAME);
        }

    }

    @Test
    public void testExecuteWithMissingArgs() throws PublisherExistsException, AuthorizationDeniedException {
        LdapPublisher publisher = new LdapPublisher();
        publisher.setHostnames("myhost1");
        publisherProxySession.addPublisher(admin, PUBLISHER_NAME, publisher);
        try {
            LdapPublisher pub1 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertEquals("Hostnames was not added as it should", "myhost1", pub1.getHostnames());
            command.execute(MISSING_ARGS);
            // Check that nothing happened
            LdapPublisher pub2 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertEquals("Hostnames was not changed as it should", "myhost1", pub2.getHostnames());
        } finally {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
        }
    }

    @Test
    public void testExecuteWithInvalidField() throws PublisherExistsException, AuthorizationDeniedException {
        LdapPublisher publisher = new LdapPublisher();
        publisher.setHostnames("myhost1");
        publisherProxySession.addPublisher(admin, PUBLISHER_NAME, publisher);
        try {
            LdapPublisher pub1 = (LdapPublisher) publisherSession.getPublisher(PUBLISHER_NAME);
            assertEquals("Hostnames was not added as it should", "myhost1", pub1.getHostnames());
            command.execute(INVALID_FIELD_ARGS);
            //TODO: Verify that publisher is unchanged
        } finally {
            publisherProxySession.removePublisherInternal(admin, PUBLISHER_NAME);
        }
    }

}
