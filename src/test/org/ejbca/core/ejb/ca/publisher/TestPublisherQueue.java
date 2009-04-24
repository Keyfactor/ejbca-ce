/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.ra.ExtendedInformation;

/**
 * Tests Publisher Queue Data.
 *
 * @version $Id$
 */
public class TestPublisherQueue extends TestCase {

    private static Context ctx;
    private static IPublisherQueueSessionHome home;
    private static IPublisherQueueSessionRemote remote;

    public TestPublisherQueue(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        ctx = getInitialContext();
        Object obj = ctx.lookup(IPublisherQueueSessionHome.JNDI_NAME);
        home = (IPublisherQueueSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IPublisherQueueSessionHome.class);
        remote = home.create();
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        Context ctx = new javax.naming.InitialContext();
        return ctx;
    }

    public void test01QueueData() throws Exception {
    	remote.addQueueData(123456, "XX", null);
    	Collection<PublisherQueueData> c = remote.getEntriesForPublisher(12345);
    	assertEquals(0, c.size());
    	c = remote.getEntriesForPublisher(123456);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals("XX", d.getFingerprint());
    	assertNull(d.getTimePublish());
    	assertNotNull(d.getTimeCreated());
    	assertEquals(PublisherQueueData.STATUS_PENDING, d.getPublishStatus());
    	assertEquals(0,d.getTryCounter());
    	assertNull(d.getVolatileData());
    	
    	Date now = new Date();
    	remote.updateData(d.getPk(), PublisherQueueData.STATUS_SUCCESS, now, 4);

    	PublisherQueueVolatileData vd = new PublisherQueueVolatileData();
    	vd.setUsername("foo");
    	vd.setPassword("bar");
    	ExtendedInformation ei = new ExtendedInformation();
    	ei.setSubjectDirectoryAttributes("directoryAttr");
    	vd.setExtendedInformation(ei);
    	remote.addQueueData(123456, "YY", vd);
    	
    	c = remote.getEntriesForPublisher(123456);
    	assertEquals(2, c.size());
    	boolean testedXX = false;
    	boolean testedYY = false;
    	i = c.iterator();
    	while (i.hasNext()) {
        	d = i.next();
        	if (d.getFingerprint().equals("XX")) {
            	assertNotNull(d.getTimePublish());
            	assertNotNull(d.getTimeCreated());
            	assertEquals(PublisherQueueData.STATUS_SUCCESS, d.getPublishStatus());
            	assertEquals(4,d.getTryCounter());
            	testedXX = true;
        	}
        	if (d.getFingerprint().equals("YY")) {
            	assertEquals(PublisherQueueData.STATUS_PENDING, d.getPublishStatus());
            	assertEquals(0,d.getTryCounter());
            	PublisherQueueVolatileData v = d.getVolatileData();
            	assertEquals("bar", v.getPassword());
            	assertEquals("foo", v.getUsername());
            	ExtendedInformation e = v.getExtendedInformation();
            	assertNotNull(e);
            	assertEquals("directoryAttr", e.getSubjectDirectoryAttributes());
            	testedYY = true;
        	}
    	}
    	assertTrue(testedXX);
    	assertTrue(testedYY);
    	
    }

    public void test99CleanUp() throws Exception {
    	Collection<PublisherQueueData> c = remote.getEntriesForPublisher(123456);
    	Iterator<PublisherQueueData> i = c.iterator();
    	while (i.hasNext()) {
        	PublisherQueueData d = i.next();
        	remote.removeQueueData(d.getPk());
    	}    	
    }
}
