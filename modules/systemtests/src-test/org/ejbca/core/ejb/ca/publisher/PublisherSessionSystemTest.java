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

package org.ejbca.core.ejb.ca.publisher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertFalse;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;

/**
 * Tests Publisher session.
 * 
 * @version $Id$
 */
public class PublisherSessionSystemTest {

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("PublisherSessionSystemTest"));
    private static final String PUBLISHER_NAME_PREFIX = "PublisherSessionSystemTest";

    private String originalCacheTime;
    private PublisherSessionRemote publisherSession;
    private PublisherProxySessionRemote publisherProxySession;
    private ConfigurationSessionRemote configSession;
    private int nextPublisherIndex;

    private String getNextPublisherName() {
        final var element = new Exception().getStackTrace()[1];
        return PUBLISHER_NAME_PREFIX + "_" + element.getMethodName()+ "_" + nextPublisherIndex++;
    }

    private Collection<String> getCurrentPublisherNames() {
        return publisherSession.getPublisherIdToNameMap().values();
    }

    private void removeAddedPublishers() throws AuthorizationDeniedException, ReferencesToItemExistException {
        final var currentPublisherNames = getCurrentPublisherNames();
        for (String publisherName : currentPublisherNames) {
            if (publisherName.startsWith(PUBLISHER_NAME_PREFIX)) {
                publisherSession.removePublisher(internalAdmin, publisherName);
            }
        }
    }

    @Before
    public void setUp() throws Exception {
        configSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        originalCacheTime = configSession.getProperty("publisher.cachetime");
        publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
        publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        removeAddedPublishers();
        nextPublisherIndex = 1;
    }

    @After
    public void tearDown() throws Exception {
        configSession.updateProperty("publisher.cachetime", originalCacheTime);
        removeAddedPublishers();
    }

    @Test
    public void testGetPublishersForPeer() throws PublisherException, AuthorizationDeniedException {
        final int peerId = 123456789;
        final String name = getNextPublisherName();

        CustomPublisherContainer publisher = new CustomPublisherContainer();
        publisher.setPropertyData("peerId=" + peerId);

        try {
            publisherProxySession.addPublisher(internalAdmin, name, publisher);
            assertFalse(publisherProxySession.getPublishersForPeer(peerId).isEmpty());
        } catch (PublisherExistsException e) {
            e.printStackTrace();
        } finally {
            publisherProxySession.removePublisherInternal(internalAdmin, name);
        }
    }

    @Test
    public void testAddAndGetByName() throws AuthorizationDeniedException, PublisherExistsException, InterruptedException {
        // Given
        final LdapPublisher publisher = new LdapPublisher();
        publisher.setBaseDN("foo");
        publisher.setDescription("foobar");
        final String name = getNextPublisherName();

        // When
        publisherProxySession.addPublisher(internalAdmin, name, publisher);

        // Then
        assertNotNull(publisherSession.getPublisher(name));
        assertNotEquals(Integer.valueOf(0), publisherProxySession.getPublisherId(name));
    }

    @Test
    public void testAddChangeRemovePublisher() throws PublisherExistsException, AuthorizationDeniedException, InterruptedException {
        // Given
        final LdapPublisher publisher_1 = new LdapPublisher();
        publisher_1.setBaseDN("foo");
        publisher_1.setDescription("foobar");
        final LdapPublisher publisher_2 = new LdapPublisher();
        publisher_2.setBaseDN("bar");
        publisher_2.setDescription("barfoo");
        final String name_1 = getNextPublisherName();
        final String name_2 = getNextPublisherName();

        // Test some initial empty checks to see we do not get NPEs
        int noId = publisherProxySession.getPublisherId(name_1);
        assertEquals("There is no publisher with the name: " + name_1, 0, noId);
        String noName = publisherProxySession.getPublisherName(123);
        assertNull("There is no publisher with the id: 123", noName);
        // Add new publisher
        publisherProxySession.addPublisher(internalAdmin, name_1, publisher_1);
        publisherProxySession.addPublisher(internalAdmin, name_2, publisher_2);
        BasePublisher pub = publisherSession.getPublisher(name_1);
        assertNotNull(pub);
        assertEquals("Description is not what we set", "foobar", pub.getDescription());
        assertEquals("Publisher is not a LdapPublisher", LdapPublisher.class.getName(), pub.getClass().getName());
        assertEquals("datasource is not what we set", "foo", ((LdapPublisher)pub).getBaseDN());
        int id = publisherProxySession.getPublisherId(name_1);
        assertNotEquals(0, id);
        BasePublisher pub1 = publisherSession.getPublisher(id);
        assertNotNull(pub1);
        assertEquals("Description is not what we set", "foobar", pub1.getDescription());
        assertEquals("Publisher is not a LdapPublisher", LdapPublisher.class.getName(), pub1.getClass().getName());
        assertEquals("datasource is not what we set", "foo", ((LdapPublisher)pub1).getBaseDN());
        // Change publisher
        pub.setDescription("newdesc");
        publisherSession.changePublisher(internalAdmin, name_1, pub);
        BasePublisher received = publisherSession.getPublisher(name_1);
        assertEquals("Description is not what we set", "newdesc", received.getDescription());
        assertEquals("Publisher is not a LdapPublisher", LdapPublisher.class.getName(), received.getClass().getName());
        assertEquals("datasource is not what we set", "foo", ((LdapPublisher)received).getBaseDN());
        int id1 = publisherProxySession.getPublisherId(name_1);
        assertEquals("Id should be the same after change, but it is not", id, id1);
        // Remove publishers
        publisherProxySession.removePublisherInternal(internalAdmin, name_1);
        publisherProxySession.removePublisherInternal(internalAdmin, name_2);
        assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(name_1));
        assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(name_2));
        assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(id));
    }
    
    /**
     * Test of the cache of publishers. This test depends on the default cache time of 1 second being used.
     * If you changed this config, publisher.cachetime, this test may fail. 
     */
    @Test
    public void testPublisherCache() throws Exception {
        // First make sure we have the right cache time
        configSession.updateProperty("publisher.cachetime", "1000");
        LdapPublisher addedPublisher = new LdapPublisher();
        addedPublisher.setDescription("foobar");
        final String name = getNextPublisherName();

        // Add a publisher
        publisherProxySession.addPublisher(internalAdmin, name, addedPublisher);
        // Make sure publisher has the right value from the beginning
        final BasePublisher actualPublisher_1 = publisherSession.getPublisher(name);
        assertEquals("Description is not what we set", addedPublisher.getDescription(), actualPublisher_1.getDescription());
        // Change publisher
        actualPublisher_1.setDescription("bar");
        publisherSession.changePublisher(internalAdmin, name, actualPublisher_1);
        // Read publisher again, cache should have been updated directly
        final BasePublisher actualPublisher_2 = publisherSession.getPublisher(name);
        assertEquals("bar", actualPublisher_2.getDescription());
        // Flush caches to reset cache timeout
        publisherProxySession.flushPublisherCache();
        /// Read publisher to ensure it is in cache
        final BasePublisher actualPublisher_3 = publisherSession.getPublisher(name);
        assertEquals("bar", actualPublisher_3.getDescription());
    }

}
