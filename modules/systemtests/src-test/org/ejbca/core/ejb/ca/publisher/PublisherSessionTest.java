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
import static org.junit.Assert.assertNull;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests Publisher session.
 * 
 * @version $Id$
 */
public class PublisherSessionTest {

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("PublisherSessionTest"));

    private PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private ConfigurationSessionRemote configSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testAddChangeRemovePublisher() throws PublisherExistsException, AuthorizationDeniedException {
        LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("foo");
        publ.setDescription("foobar");
        LdapPublisher publ1 = new LdapPublisher();
        publ1.setBaseDN("bar");
        publ1.setDescription("barfoo");
        final String name = PublisherSessionTest.class.getSimpleName();
        final String name1 = PublisherSessionTest.class.getSimpleName()+"1";
        try {
            // Test some initial empty checks to see we do not get NPEs
            int noid = publisherProxySession.getPublisherId(name);
            assertEquals(0, noid);
            String noname = publisherProxySession.getPublisherName(123);
            assertNull(noname);
            // Add new publisher
            publisherProxySession.addPublisher(internalAdmin, name, publ);
            publisherProxySession.addPublisher(internalAdmin, name1, publ1);
            BasePublisher pub = publisherSession.getPublisher(name);
            assertEquals("Description is not what we set", "foobar", pub.getDescription());
            assertEquals("Publisher is not a LdapPublisher", LdapPublisher.class.getName(), pub.getClass().getName());
            assertEquals("datasource is not what we set", "foo", ((LdapPublisher)pub).getBaseDN());
            int id = publisherProxySession.getPublisherId(name);
            BasePublisher pub1 = publisherSession.getPublisher(id);
            assertEquals("Description is not what we set", "foobar", pub1.getDescription());
            assertEquals("Publisher is not a LdapPublisher", LdapPublisher.class.getName(), pub1.getClass().getName());
            assertEquals("datasource is not what we set", "foo", ((LdapPublisher)pub1).getBaseDN());
            // Change publisher
            pub.setDescription("newdesc");
            publisherSession.changePublisher(internalAdmin, name, pub);
            pub = publisherSession.getPublisher(name);
            assertEquals("Description is not what we set", "newdesc", pub.getDescription());
            assertEquals("Publisher is not a LdapPublisher", LdapPublisher.class.getName(), pub.getClass().getName());
            assertEquals("datasource is not what we set", "foo", ((LdapPublisher)pub).getBaseDN());
            int id1 = publisherProxySession.getPublisherId(name);
            assertEquals("Id should be the same after change, but it is not", id, id1);
            // Remove publishers
            publisherProxySession.removePublisherInternal(internalAdmin, name);
            publisherProxySession.removePublisherInternal(internalAdmin, name1);
            assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(name));
            assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(name1));
            assertNull("Should return null when publisher does not exist", publisherSession.getPublisher(id));
        } finally {
            publisherProxySession.removePublisherInternal(internalAdmin, name);
            publisherProxySession.removePublisherInternal(internalAdmin, name1);            
        }
    }
    
    /**
     * Test of the cache of publishers. This test depends on the default cache time of 1 second being used.
     * If you changed this config, publisher.cachetime, this test may fail. 
     */
    @Test
    public void testPublisherCache() throws Exception {
        // First make sure we have the right cache time
        final String oldcachetime = configSession.getProperty("publisher.cachetime");
        configSession.updateProperty("publisher.cachetime", "1000");
        LdapPublisher publ = new LdapPublisher();
        publ.setDescription("foobar");
        final String name = PublisherSessionTest.class.getSimpleName();
        try {
            // Add a publisher
            publisherProxySession.addPublisher(internalAdmin, name, publ);
            // Make sure publisher has the right value from the beginning
            BasePublisher pub = publisherSession.getPublisher(name);
            assertEquals("Description is not what we set", "foobar", pub.getDescription());
            // Change publisher
            pub.setDescription("bar");
            publisherSession.changePublisher(internalAdmin, name, pub);
            // Read publisher again, cache should have been updated directly
            pub = publisherSession.getPublisher(name);
            assertEquals("bar", pub.getDescription());
            // Flush caches to reset cache timeout
            publisherProxySession.flushPublisherCache();
            /// Read publisher to ensure it is in cache
            pub = publisherSession.getPublisher(name);
            assertEquals("bar", pub.getDescription());
            // Change publisher not flushing cache, old value should remain when reading
            pub.setDescription("newvalue");
            publisherProxySession.internalChangePublisherNoFlushCache(name, pub);
            pub = publisherSession.getPublisher(name);
            assertEquals("bar", pub.getDescription()); // old value
            // Wait 2 seconds and try again, now the cache should have been updated
            Thread.sleep(2000);
            pub = publisherSession.getPublisher(name);
            assertEquals("newvalue", pub.getDescription()); // new value
        } finally {
            configSession.updateProperty("publisher.cachetime", oldcachetime);
            publisherProxySession.removePublisherInternal(internalAdmin, name);
        }
    } 

}
