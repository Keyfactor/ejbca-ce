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

package org.ejbca.core.model.services;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;
import java.util.Random;

import junit.framework.TestCase;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.TestTools;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id$
 */
public class PublisherQueueProcessTest extends TestCase {

    //private static final Logger log = Logger.getLogger(TestPublisherQueueProcess.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    private static byte[] testcert = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
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

    /**
     * Creates a new TestUserPasswordExpire object.
     *
     * @param name DOCUMENT ME!
     */
    public PublisherQueueProcessTest(String name) throws Exception {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        return username;
    } // genRandomUserName


    /** Add a new entry to the publisher queue and let the process service run, with no publisher.
     *
     */
    public void test01PublishQueueProcessFail() throws Exception {
    	TestTools.getPublisherQueueSession().addQueueData(12345, PublisherQueueData.PUBLISH_TYPE_CERT, "TestPublishQueueProcessService12345", null, PublisherQueueData.STATUS_PENDING);
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(12345);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals(0,d.getTryCounter());    	

        // Create a new PublisherQueueProcess service
		ServiceConfiguration config = new ServiceConfiguration();
		config.setActive(true);
		config.setDescription("This is a description");
		// No mailsending for this Junit test service
		config.setActionClassPath(NoAction.class.getName());
		config.setActionProperties(null); 
		config.setIntervalClassPath(PeriodicalInterval.class.getName());
		Properties intervalprop = new Properties();
		// Run the service every 3:rd second
		intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
		intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
		config.setIntervalProperties(intervalprop);
		config.setWorkerClassPath(PublishQueueProcessWorker.class.getName());
		Properties workerprop = new Properties();
		workerprop.setProperty(PublishQueueProcessWorker.PROP_PUBLISHER_IDS, "12345");
		config.setWorkerProperties(workerprop);
		
		TestTools.getServiceSession().addService(admin, "TestPublishQueueProcessService12345", config);
        TestTools.getServiceSession().activateServiceTimer(admin, "TestPublishQueueProcessService12345");
        
        // The service will run...
        Thread.sleep(5000);
        
        // Now the publisher 12345 will not have existed so we should have updated the publish entry's tryCounter
    	c = TestTools.getPublisherQueueSession().getEntriesByFingerprint("TestPublishQueueProcessService12345");
    	assertEquals(1, c.size());
    	i = c.iterator();
    	d = i.next();
    	assertEquals(1,d.getTryCounter());    	
    	assertEquals(PublisherQueueData.STATUS_PENDING, d.getPublishStatus());
    }

    /** Add a new entry to the publisher queue and let the process service run, with a publisher.
    *
    */
    public void test01PublishQueueProcessSuccess() throws Exception {
    	// Add a Dummy publisher with Id 12345
    	try {
    		CustomPublisherContainer publisher = new CustomPublisherContainer();
    		publisher.setKeepPublishedInQueue(true);
    		publisher.setClassPath("org.ejbca.core.model.ca.publisher.DummyCustomPublisher");
    		publisher.setDescription("Used in Junit Test, Remove this one");
    		TestTools.getPublisherSession().addPublisher(admin, "TestPublishQueueProcessService", publisher);
    	} catch (PublisherExistsException pee) {
    	}
    	int publisherId = TestTools.getPublisherSession().getPublisherId(admin, "TestPublishQueueProcessService"); 

    	// We must add new entries to the queue, since we could not know the publisherId before
    	Certificate cert = CertTools.getCertfromByteArray(testcert);
    	try {
    		TestTools.getCertificateStoreSession().storeCertificate(admin, cert, "TestPublishQueueProcessService", null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, 12345, "tag", new Date().getTime());
    	} catch (Exception e) {
    		// Perhaps the cert already exists
    	}
    	
    	TestTools.getPublisherQueueSession().addQueueData(publisherId, PublisherQueueData.PUBLISH_TYPE_CERT, CertTools.getFingerprintAsString(testcert), null, PublisherQueueData.STATUS_PENDING);
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(publisherId);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals(0,d.getTryCounter());    	

        // Create a new PublisherQueueProcess service
		ServiceConfiguration config = new ServiceConfiguration();
		config.setActive(true);
		config.setDescription("This is a description");
		// No mailsending for this Junit test service
		config.setActionClassPath(NoAction.class.getName());
		config.setActionProperties(null); 
		config.setIntervalClassPath(PeriodicalInterval.class.getName());
		Properties intervalprop = new Properties();
		// Run the service every 3:rd second
		intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
		intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
		config.setIntervalProperties(intervalprop);
		config.setWorkerClassPath(PublishQueueProcessWorker.class.getName());
		Properties workerprop = new Properties();
		workerprop.setProperty(PublishQueueProcessWorker.PROP_PUBLISHER_IDS, String.valueOf(publisherId));
		config.setWorkerProperties(workerprop);
		
		TestTools.getServiceSession().addService(admin, "TestPublishQueueProcessService", config);
        TestTools.getServiceSession().activateServiceTimer(admin, "TestPublishQueueProcessService");

    	// Let the service run and publish the entry
    	Thread.sleep(5000);
    	// Now the entry should be published
    	// Now the publisher will not have existed so we should have updated the publish entry's tryCounter
    	c = TestTools.getPublisherQueueSession().getEntriesByFingerprint(CertTools.getFingerprintAsString(testcert));
    	assertEquals(1, c.size());
    	i = c.iterator();
    	d = i.next();
    	assertEquals(0,d.getTryCounter());    	
    	assertEquals(PublisherQueueData.STATUS_SUCCESS, d.getPublishStatus());
    }
   
    /**
     * Remove all data stored by JUnit tests
     *
     */
    public void test99CleanUp() throws Exception {
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getEntriesByFingerprint("TestPublishQueueProcessService12345");
    	Iterator<PublisherQueueData> i = c.iterator();
    	while (i.hasNext()) {
    		PublisherQueueData d = i.next();
            try {
            	TestTools.getPublisherQueueSession().removeQueueData(d.getPk());
            } catch (Exception pee) {}
    	}
    	c = TestTools.getPublisherQueueSession().getEntriesByFingerprint(CertTools.getFingerprintAsString(testcert));
    	i = c.iterator();
    	while (i.hasNext()) {
    		PublisherQueueData d = i.next();
            try {
            	TestTools.getPublisherQueueSession().removeQueueData(d.getPk());
            } catch (Exception pee) {}
    	}
        try {
        	TestTools.getServiceSession().removeService(admin, "TestPublishQueueProcessService12345");
        } catch (Exception pee) {}
        try {
        	TestTools.getServiceSession().removeService(admin, "TestPublishQueueProcessService");
        } catch (Exception pee) {}
		
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TestPublishQueueProcessService");
        } catch (Exception pee) {}

    }
}
