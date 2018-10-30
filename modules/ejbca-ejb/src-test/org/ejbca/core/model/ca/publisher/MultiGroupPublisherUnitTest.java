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
package org.ejbca.core.model.ca.publisher;

import static org.easymock.EasyMock.aryEq;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.easymock.MockType;
import org.easymock.TestSubject;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Unit test for MultiGroupPublisher.
 * @see MultiGroupPublisherSystemTest
 * @version $Id$
 */
@RunWith(EasyMockRunner.class)
public class MultiGroupPublisherUnitTest {

    private static final Logger log = Logger.getLogger(MultiGroupPublisherUnitTest.class);

    private static final String TEST_PUBLISHER_DESCRIPTION = "This is a test";
    private static final String TEST_PUBLISHER_NAME = "SomeMultiGroupPublisher";

    @Mock(MockType.NICE)
    private PublisherSessionLocal publisherSession;

    @TestSubject 
    private MultiGroupPublisher publisher = new MultiGroupPublisher();

    final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken("Dummy Admin");

    /**
     * Tests the storeCrl using a mock PublisherSession. It tests with non-existing publisher IDs, which should
     * never happen, but we should not crash if it happens.
     */
    @Test
    public void storeCrl() throws PublisherException, AuthorizationDeniedException {
        // Set up
        final List<TreeSet<Integer>> publisherGroups = new ArrayList<>();
        final TreeSet<Integer> group1 = new TreeSet<>();
        group1.add(123);
        group1.add(234);
        group1.add(345);
        group1.add(456); // this one "exists" in the mock session bean
        group1.add(567);
        publisherGroups.add(group1);
        publisher.setName(TEST_PUBLISHER_NAME);
        publisher.setPublisherGroups(publisherGroups);
        // Expected flow
        final BasePublisher referencedPublisher456 = new LdapPublisher();
        referencedPublisher456.setPublisherId(456);
        referencedPublisher456.setName("Referenced Publisher 456");
        final byte[] myCrl = new byte[] { 22, 33, 44, 55 }; // bogus data. publisher won't decode it
        expect(publisherSession.getPublisher(456)).andReturn(referencedPublisher456).once();
        expect(publisherSession.storeCRL(same(admin), eq(Arrays.asList(456)), aryEq(myCrl), eq("ABCD1234"), eq(10), eq("CN=Some CA"))).andReturn(true).once();
        replay(publisherSession);
        // Run and verify
        publisher.storeCRL(admin, myCrl, "ABCD1234", 10, "CN=Some CA");
        verify();
    }

    /**
     * Tests happy path for testConnection.
     */
    @Test
    public void testConnectionHappyPath() throws PublisherConnectionException {
        // Set up
        final List<TreeSet<Integer>> publisherGroups = new ArrayList<>();
        final TreeSet<Integer> group1 = new TreeSet<>();
        group1.add(123);
        publisherGroups.add(group1);
        publisher.setName(TEST_PUBLISHER_NAME);
        publisher.setPublisherGroups(publisherGroups);
        // Expected flow
        final BasePublisher referencedPublisher = EasyMock.createMock(LdapPublisher.class);
        expect(referencedPublisher.getPublisherId()).andReturn(123).anyTimes();
        expect(referencedPublisher.getName()).andReturn("Referenced Publisher 456").anyTimes();
        expect(publisherSession.getPublisher(123)).andReturn(referencedPublisher).once();
        referencedPublisher.testConnection();
        expectLastCall().once();
        replay(publisherSession, referencedPublisher);
        // Run and verify
        publisher.testConnection();
        verify(publisherSession, referencedPublisher);
    }

    /**
     * Tests exception handling in testConnection.
     */
    @Test
    public void testConnectionFailure() throws PublisherConnectionException {
        // Set up
        final List<TreeSet<Integer>> publisherGroups = new ArrayList<>();
        final TreeSet<Integer> group1 = new TreeSet<>();
        group1.add(123);
        publisherGroups.add(group1);
        publisher.setName(TEST_PUBLISHER_NAME);
        publisher.setPublisherGroups(publisherGroups);
        // Expected flow
        final BasePublisher referencedPublisher = EasyMock.createMock(LdapPublisher.class);
        expect(referencedPublisher.getPublisherId()).andReturn(123).anyTimes();
        expect(referencedPublisher.getName()).andReturn("Some Failing Publisher 456").anyTimes();
        expect(publisherSession.getPublisher(123)).andReturn(referencedPublisher).once();
        referencedPublisher.testConnection();
        expectLastCall().andThrow(new PublisherConnectionException("Some error 32474")).once();
        replay(publisherSession, referencedPublisher);
        // Run and verify
        try {
            publisher.testConnection();
            fail("testConnection should throw");
        } catch (PublisherConnectionException e) {
            log.debug("Exception message is: " + e);
            assertTrue("Missing cause in exception message.", e.getMessage().contains("Some error 32474"));
            assertTrue("Missing name of failed publisher in message.", e.getMessage().contains("Some Failing Publisher 456"));
        }
        verify(publisherSession, referencedPublisher);
    }

    @Test
    public void testClone() throws CloneNotSupportedException {
        final List<TreeSet<Integer>> originalPublisherGroups = new ArrayList<>();
        final TreeSet<Integer> publisherGroup1 = new TreeSet<>();
        publisherGroup1.add(456);
        publisherGroup1.add(123);
        originalPublisherGroups.add(publisherGroup1);

        final MultiGroupPublisher publisher = new MultiGroupPublisher();
        publisher.setDescription(TEST_PUBLISHER_DESCRIPTION);
        publisher.setName(TEST_PUBLISHER_NAME); 
        publisher.setOnlyUseQueue(false);
        publisher.setUseQueueForCertificates(false);
        publisher.setUseQueueForCRLs(false);
        publisher.setPublisherGroups(originalPublisherGroups);

        final MultiGroupPublisher clone = (MultiGroupPublisher) publisher.clone();
        assertEquals("Description is different", TEST_PUBLISHER_DESCRIPTION, clone.getDescription());
        // Name and id is not cloned in any of the publishers, because the clone() method is only used to copy publishers to a new name in the GUI.
        assertFalse("getOnlyUseQueue is different", clone.getOnlyUseQueue());
        assertFalse("getUseQueueForCertificates is different", clone.getUseQueueForCertificates());
        assertFalse("getUseQueueForCRLs is different", clone.getUseQueueForCRLs());
        assertNotSame("Publisher groups list was re-used", publisher.getPublisherGroups(), clone.getPublisherGroups());
        assertEquals("Publisher groups list was different", publisher.getPublisherGroups(), clone.getPublisherGroups());
    }

}
