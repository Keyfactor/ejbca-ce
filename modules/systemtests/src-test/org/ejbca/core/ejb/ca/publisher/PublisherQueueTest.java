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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;
import org.junit.After;
import org.junit.Test;

/**
 * Tests Publisher Queue Data.
 * 
 * @version $Id$
 */
//@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PublisherQueueTest {

    private static byte[] testcert = Base64.decode((
            "MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw" 
            + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" 
            + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe" 
            + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM" 
            + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS" 
            + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+" 
            + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());

    private static final Logger log = Logger.getLogger(PublisherQueueTest.class);

    private PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Test
    public void shouldFindNoPendingEntriesWhenNoneIsInserted() {
        final int publisherId = 11111;
        Collection<PublisherQueueData> c = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        assertEquals(0, c.size());
    }
    
    @Test
    public void testInsertedPendingPublisherQueueHasProperValues() throws Exception {
        final int publisherId = 11111;
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        Collection<PublisherQueueData> c = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        assertEquals(1, c.size());
        Iterator<PublisherQueueData> i = c.iterator();
        PublisherQueueData d = i.next();
        assertEquals("XX", d.getFingerprint());
        Date lastUpdate1 = d.getLastUpdate();
        assertNotNull(lastUpdate1);
        assertNotNull(d.getTimeCreated());
        assertEquals(PublisherConst.STATUS_PENDING, d.getPublishStatus());
        assertEquals(0, d.getTryCounter());
        assertNull(d.getVolatileData());
    }
        
    @Test
    public void testQueueDataHasProperValuesAfterUpdate() throws Exception {
        final int publisherId = 11111;
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        
        Collection<PublisherQueueData> c = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        Iterator<PublisherQueueData> iterator = c.iterator();
        PublisherQueueData publisherQueueData1 = iterator.next();
        assertEquals("XX", publisherQueueData1.getFingerprint());
        Date lastUpdate1 = publisherQueueData1.getLastUpdate();
        
        String xxpk = publisherQueueData1.getPk(); // Keep for later so we can set to success

        PublisherQueueVolatileInformation vd = new PublisherQueueVolatileInformation();
        vd.setUsername("foo");
        vd.setPassword("bar");
        ExtendedInformation ei = new ExtendedInformation();
        ei.setSubjectDirectoryAttributes("directoryAttr");
        vd.setExtendedInformation(ei);
        
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CRL, "YY", vd, PublisherConst.STATUS_PENDING);

        c = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        assertEquals(2, c.size());
        boolean testedXX = false;
        boolean testedYY = false;

        iterator = c.iterator();
        while (iterator.hasNext()) {
            publisherQueueData1 = iterator.next();
            if (publisherQueueData1.getFingerprint().equals("XX")) {
                assertEquals(PublisherConst.PUBLISH_TYPE_CERT, publisherQueueData1.getPublishType());
                assertNotNull(publisherQueueData1.getLastUpdate());
                assertNotNull(publisherQueueData1.getTimeCreated());
                assertEquals(PublisherConst.STATUS_PENDING, publisherQueueData1.getPublishStatus());
                assertEquals(0, publisherQueueData1.getTryCounter());
                testedXX = true;
            }
            if (publisherQueueData1.getFingerprint().equals("YY")) {
                assertEquals(PublisherConst.PUBLISH_TYPE_CRL, publisherQueueData1.getPublishType());
                assertEquals(PublisherConst.STATUS_PENDING, publisherQueueData1.getPublishStatus());
                assertEquals(0, publisherQueueData1.getTryCounter());
                PublisherQueueVolatileInformation v = publisherQueueData1.getVolatileData();
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

        publisherQueueSession.updateData(xxpk, PublisherConst.STATUS_SUCCESS, 4);
        
        c = publisherQueueSession.getEntriesByFingerprint("XX");
        assertEquals(1, c.size());
        iterator = c.iterator();
        publisherQueueData1 = iterator.next();
        assertEquals("XX", publisherQueueData1.getFingerprint());
        Date lastUpdate2 = publisherQueueData1.getLastUpdate();
        
        assertTrue(lastUpdate2.after(lastUpdate1));
        assertNotNull(publisherQueueData1.getTimeCreated());
        assertEquals(PublisherConst.STATUS_SUCCESS, publisherQueueData1.getPublishStatus());
        assertEquals(4, publisherQueueData1.getTryCounter());
    }

    
    @Test
    public void shouldFindPendingPublisherQueueCountsWithoutCreatedTimeUpperIntervals() throws Exception {
        final int publisherId = 22222;
        // Nothing in the queue from the beginning
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 })[0]);

        // Add data
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);

        // One entry in the queue
        assertEquals(1, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        int[] actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 });
        assertEquals(1, actual.length);
        assertEquals(1, actual[0]);

        // Wait a while and then add some more data
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ex) {
            fail(ex.getMessage());
        }
        // Another entry in the queue, atleast 1s after the first one
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);

        actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0, 1, 10 }, new int[] { -1, -1, -1 });
        assertEquals(3, actual.length);
        assertEquals(2, actual[0]); // 0s old = 2
        assertEquals(1, actual[1]); // 1s old = 1
        assertEquals(0, actual[2]); // 10s old = 0
    }

    @Test
    public void shouldFindPendingPublisherQueueCountsWithCreatedTimeIntervals() throws Exception {

        final int publisherId = 33333;

        // verify that there is nothing in the queue in the beginning
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 })[0]);

        // add 1st entry
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added data at: "+System.currentTimeMillis());

        // verify that there is now one entry in the queue
        assertEquals(1, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        int[] actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 });
        assertEquals(1, actual.length);
        assertEquals(1, actual[0]);

        log.debug("Sleeping at: "+System.currentTimeMillis());
        // wait for a while before adding 2nd entry
        try {
            Thread.sleep(6000);
        } catch (InterruptedException ex) {
            fail(ex.getMessage());
        }

        // add 2nd entry into the queue, at least 3s after the first one
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added new data at: "+System.currentTimeMillis());

        int[] lowerCreatedTimeSearchCriteria = {0, 0, 3, 10};
        int[] upperCreateTimeSearchCriteria = {-1, 3, 10, -1};
        actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, lowerCreatedTimeSearchCriteria, upperCreateTimeSearchCriteria);
        log.debug("Returned at "+System.currentTimeMillis()+", actual=" + Arrays.toString(actual));

        assertEquals(4, actual.length);
        assertEquals(2, actual[0]); // (~, ~) s = 2
        assertEquals(1, actual[1]); // (~, 3) s  = 1
        assertEquals(1, actual[2]); // (3, 10) s = 1
        assertEquals(0, actual[3]); // (10, ~) s = 0
    }

    @Test
    public void shouldFindPendingPublisherQueueCountsWithCreatedTimeIntervalsNullAndThree_01() throws Exception {

        final int publisherId = 33333;

        // verify that there is nothing in the queue in the beginning
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 })[0]);

        // add 1st entry
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added data at: "+System.currentTimeMillis());

        // verify that there is now one entry in the queue
        assertEquals(1, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        int[] actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 });
        assertEquals(1, actual.length);
        assertEquals(1, actual[0]);

        log.debug("Sleeping at: "+System.currentTimeMillis());
        // wait for a while before adding 2nd entry
        try {
            Thread.sleep(6000);
        } catch (InterruptedException ex) {
            fail(ex.getMessage());
        }

        // add 2nd entry into the queue, at least 3s after the first one
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added new data at: "+System.currentTimeMillis());

        int[] lowerCreatedTimeSearchCriteria = {0};
        int[] upperCreateTimeSearchCriteria = {3};
        actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, lowerCreatedTimeSearchCriteria, upperCreateTimeSearchCriteria);
        log.debug("Returned at "+System.currentTimeMillis()+", actual=" + Arrays.toString(actual));

        assertEquals(1, actual.length);
        assertEquals(1, actual[0]); // (~, 3) s  = 1

    }

    @Test
    public void shouldFindPendingPublisherQueueCountsWithCreatedTimeIntervalsThreeAndTen_02() throws Exception {

        final int publisherId = 33333;

        // verify that there is nothing in the queue in the beginning
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 })[0]);

        // add 1st entry
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added data at: "+System.currentTimeMillis());

        // verify that there is now one entry in the queue
        assertEquals(1, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        int[] actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 });
        assertEquals(1, actual.length);
        assertEquals(1, actual[0]);

        log.debug("Sleeping at: "+System.currentTimeMillis());
        // wait for a while before adding 2nd entry
        try {
            Thread.sleep(6000);
        } catch (InterruptedException ex) {
            fail(ex.getMessage());
        }

        // add 2nd entry into the queue, at least 3s after the first one
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added new data at: "+System.currentTimeMillis());

        int[] lowerCreatedTimeSearchCriteria = {3};
        int[] upperCreateTimeSearchCriteria = {10};
        actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, lowerCreatedTimeSearchCriteria, upperCreateTimeSearchCriteria);
        log.debug("Returned at "+System.currentTimeMillis()+", actual=" + Arrays.toString(actual));

        assertEquals(1, actual.length);
        assertEquals(1, actual[0]); // (3, 10) s = 1
    }

    @Test
    public void shouldFindPendingPublisherQueueCountsWithCreatedTimeIntervalsTenAndNull_03() throws Exception {
	
        final int publisherId = 33333;

        // verify that there is nothing in the queue in the beginning
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 })[0]);

        // add 1st entry
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added data at: "+System.currentTimeMillis());

        // verify that there is now one entry in the queue
        assertEquals(1, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        int[] actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 });
        assertEquals(1, actual.length);
        assertEquals(1, actual[0]);

        log.debug("Sleeping at: "+System.currentTimeMillis());
        // wait for a while before adding 2nd entry
        try {
            Thread.sleep(6000);
        } catch (InterruptedException ex) {
            fail(ex.getMessage());
        }

        // add 2nd entry into the queue, at least 3s after the first one
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added new data at: "+System.currentTimeMillis());

        int[] lowerCreatedTimeSearchCriteria = {10};
        int[] upperCreateTimeSearchCriteria = {-1};
        actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, lowerCreatedTimeSearchCriteria, upperCreateTimeSearchCriteria);
        log.debug("Returned at "+System.currentTimeMillis()+", actual=" + Arrays.toString(actual));        
        
        assertEquals(1, actual.length);
        assertEquals(0, actual[0]); // (10, ~) s = 0
    }

    @Test
    public void shouldFindPendingPublisherQueueCountsWithCreatedTimeIntervalsBothBoundsNull_04() throws Exception {

        final int publisherId = 33333;

        // verify that there is nothing in the queue in the beginning
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        assertEquals(0, publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 })[0]);

        // add 1st entry
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added data at: "+System.currentTimeMillis());

        // verify that there is now one entry in the queue
        assertEquals(1, publisherQueueSession.getPendingEntriesCountForPublisher(publisherId));
        int[] actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, new int[] { 0 }, new int[] { -1 });
        assertEquals(1, actual.length);
        assertEquals(1, actual[0]);

        log.debug("Sleeping at: "+System.currentTimeMillis());
        // wait for a while before adding 2nd entry
        try {
            Thread.sleep(6000);
        } catch (InterruptedException ex) {
            fail(ex.getMessage());
        }

        // add 2nd entry into the queue, at least 3s after the first one
        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, "XX", null, PublisherConst.STATUS_PENDING);
        log.debug("Added new data at: "+System.currentTimeMillis());

        int[] lowerCreatedTimeSearchCriteria = {0};
        int[] upperCreateTimeSearchCriteria = {-1};
        actual = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, lowerCreatedTimeSearchCriteria, upperCreateTimeSearchCriteria);
        log.debug("Returned at "+System.currentTimeMillis()+", actual=" + Arrays.toString(actual));

        assertEquals(1, actual.length);
        assertEquals(2, actual[0]); // (~, ~) s = 2
    }

    @After
    public void cleanUp() throws Exception {
        PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        for(PublisherQueueData d : publisherQueueSession.getEntriesByFingerprint("XX")) {
            publisherQueueSession.removeQueueData(d.getPk());
        }
        for(PublisherQueueData d : publisherQueueSession.getEntriesByFingerprint("YY")) {
            publisherQueueSession.removeQueueData(d.getPk());
        }
        for(PublisherQueueData d : publisherQueueSession.getEntriesByFingerprint(CertTools.getFingerprintAsString(testcert))) {
            publisherQueueSession.removeQueueData(d.getPk());
        }
        // If the dummy cert was put in the database, remove it
        Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
        internalCertificateStoreSession.removeCertificate(cert);
    }
}
