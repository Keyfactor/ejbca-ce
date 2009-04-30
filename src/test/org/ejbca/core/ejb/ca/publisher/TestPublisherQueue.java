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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import junit.framework.TestCase;

import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.ExternalOCSPPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.TestTools;

/**
 * Tests Publisher Queue Data.
 *
 * @version $Id$
 */
public class TestPublisherQueue extends TestCase {

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

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    public TestPublisherQueue(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    public void test01QueueData() throws Exception {
    	TestTools.getPublisherQueueSession().addQueueData(123456, PublisherQueueData.PUBLISH_TYPE_CERT, "XX", null);
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(12345);
    	assertEquals(0, c.size());
    	c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(123456);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals("XX", d.getFingerprint());
    	assertNull(d.getTimePublish());
    	assertNotNull(d.getTimeCreated());
    	assertEquals(PublisherQueueData.STATUS_PENDING, d.getPublishStatus());
    	assertEquals(0,d.getTryCounter());
    	assertNull(d.getVolatileData());
    	
    	String xxpk = d.getPk(); // Keep for later so we can set to success
    	
    	PublisherQueueVolatileData vd = new PublisherQueueVolatileData();
    	vd.setUsername("foo");
    	vd.setPassword("bar");
    	ExtendedInformation ei = new ExtendedInformation();
    	ei.setSubjectDirectoryAttributes("directoryAttr");
    	vd.setExtendedInformation(ei);
    	TestTools.getPublisherQueueSession().addQueueData(123456, PublisherQueueData.PUBLISH_TYPE_CRL, "YY", vd);
    	
    	c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(123456);
    	assertEquals(2, c.size());
    	boolean testedXX = false;
    	boolean testedYY = false;
    	i = c.iterator();
    	while (i.hasNext()) {
        	d = i.next();
        	if (d.getFingerprint().equals("XX")) {
        		assertEquals(PublisherQueueData.PUBLISH_TYPE_CERT, d.getPublishType());
            	assertNull(d.getTimePublish());
            	assertNotNull(d.getTimeCreated());
            	assertEquals(PublisherQueueData.STATUS_PENDING, d.getPublishStatus());
            	assertEquals(0,d.getTryCounter());
            	testedXX = true;
        	}
        	if (d.getFingerprint().equals("YY")) {
        		assertEquals(PublisherQueueData.PUBLISH_TYPE_CRL, d.getPublishType());
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
    	
    	Date now = new Date();
    	TestTools.getPublisherQueueSession().updateData(xxpk, PublisherQueueData.STATUS_SUCCESS, now, 4);
    	c = TestTools.getPublisherQueueSession().getEntriesByFingerprint("XX");
    	assertEquals(1, c.size());
    	i = c.iterator();
    	d = i.next();
    	assertEquals("XX", d.getFingerprint());
    	assertNotNull(d.getTimePublish());
    	assertNotNull(d.getTimeCreated());
    	assertEquals(PublisherQueueData.STATUS_SUCCESS, d.getPublishStatus());
    	assertEquals(4,d.getTryCounter());    	
    }

    public void test02ExternalOCSPPublisherFail() throws Exception {
        boolean ret = false;

        ret = false;
		try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ExternalOCSPPublisher.class.getName());
		    // We use a datasource that we know don't exist, so we know publishing will fail
            publisher.setPropertyData("dataSource java:/NoExist234DS");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTEXTOCSPQUEUE", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	// Do nothing
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSPQUEUE");
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSPQUEUE")));
        
        ret = TestTools.getPublisherSession().storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, CertificateDataBean.CERT_ACTIVE, CertificateDataBean.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, null);
        assertFalse("Storing certificate to external ocsp publisher should fail.", ret);
        
        // Now this certificate fingerprint should be in the queue
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(id);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals(CertTools.getFingerprintAsString(cert), d.getFingerprint());
    	
    }

    public void test03ExternalOCSPPublisherOk() throws Exception {
        boolean ret = false;

        // Remove publisher since we probably have one from the test above
    	try {
    		TestTools.getPublisherSession().removePublisher(admin, "TESTEXTOCSPQUEUE");            
    	} catch (Exception pee) {}

        ret = false;
		try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ExternalOCSPPublisher.class.getName());
		    // We use a datasource that we know don't exist, so we know publishing will fail
            publisher.setPropertyData("dataSource java:/EjbcaDS");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTEXTOCSPQUEUE", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	// Do nothing
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSPQUEUE");
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSPQUEUE")));
        
        ret = TestTools.getPublisherSession().storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, CertificateDataBean.CERT_ACTIVE, CertificateDataBean.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, null);
        assertTrue("Storing certificate to external ocsp publisher should succeed.", ret);
        
        // Now this certificate fingerprint should NOT be in the queue
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(id);
    	assertEquals(0, c.size());
    }
    
    public void test04ExternalOCSPPublisherOnlyUseQueue() throws Exception {
        boolean ret = false;

        // Remove publisher since we probably have one from the test above
    	try {
    		TestTools.getPublisherSession().removePublisher(admin, "TESTEXTOCSPQUEUE");            
    	} catch (Exception pee) {}
        
        ret = false;
		try {
			CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ExternalOCSPPublisher.class.getName());
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
            publisher.setPropertyData("dataSource java:/EjbcaDS");
            publisher.setDescription("Used in Junit Test, Remove this one");
            
            // Set to only use the publisher queue instead of publish directly
            publisher.setOnlyUseQueue(true);
            
            TestTools.getPublisherSession().addPublisher(admin, "TESTEXTOCSPQUEUE", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	// Do nothing
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSPQUEUE");
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSPQUEUE")));
        
        // storeCertificate should return false as we have not published to all publishers but instead only pushed to the queue
        ret = TestTools.getPublisherSession().storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, CertificateDataBean.CERT_ACTIVE, CertificateDataBean.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, null);
        assertFalse("Storing certificate to all external ocsp publisher should return false.", ret);
        
        // Now this certificate fingerprint should be in the queue
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getPendingEntriesForPublisher(id);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals(CertTools.getFingerprintAsString(cert), d.getFingerprint());
    }
    
    public void test99CleanUp() throws Exception {
    	Collection<PublisherQueueData> c = TestTools.getPublisherQueueSession().getEntriesByFingerprint("XX");
    	Iterator<PublisherQueueData> i = c.iterator();
    	while (i.hasNext()) {
    		PublisherQueueData d = i.next();
    		TestTools.getPublisherQueueSession().removeQueueData(d.getPk());
    	}    
    	c = TestTools.getPublisherQueueSession().getEntriesByFingerprint("YY");
    	i = c.iterator();
    	while (i.hasNext()) {
    		PublisherQueueData d = i.next();
    		TestTools.getPublisherQueueSession().removeQueueData(d.getPk());
    	}    
    	c = TestTools.getPublisherQueueSession().getEntriesByFingerprint(CertTools.getFingerprintAsString(testcert));
    	i = c.iterator();
    	while (i.hasNext()) {
    		PublisherQueueData d = i.next();
    		TestTools.getPublisherQueueSession().removeQueueData(d.getPk());
    	}    

    	try {
    		TestTools.getPublisherSession().removePublisher(admin, "TESTEXTOCSPQUEUE");            
    	} catch (Exception pee) {}
    }
}
