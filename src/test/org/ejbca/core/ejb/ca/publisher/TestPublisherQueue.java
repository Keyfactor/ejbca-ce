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

import javax.naming.Context;
import javax.naming.NamingException;

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

    private static Context ctx;
    private static IPublisherQueueSessionRemote remote;
    private static IPublisherSessionRemote pub;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    public TestPublisherQueue(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        ctx = getInitialContext();
        Object obj = ctx.lookup(IPublisherQueueSessionHome.JNDI_NAME);
        IPublisherQueueSessionHome home = (IPublisherQueueSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IPublisherQueueSessionHome.class);
        remote = home.create();

        obj = ctx.lookup(IPublisherSessionHome.JNDI_NAME);
        IPublisherSessionHome phome = (IPublisherSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IPublisherSessionHome.class);
        pub = phome.create();

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

    public void test02ExternalOCSPPublisherFail() throws Exception {
        boolean ret = false;

        ret = false;
		try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ExternalOCSPPublisher.class.getName());
		    // We use a datasource that we know don't exist, so we know publishing will fail
            publisher.setPropertyData("dataSource java:/NoExist234DS");
            publisher.setDescription("Used in Junit Test, Remove this one");
            pub.addPublisher(admin, "TESTEXTOCSPQUEUE", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	// Do nothing
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = pub.getPublisherId(admin, "TESTEXTOCSPQUEUE");
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(pub.getPublisherId(admin, "TESTEXTOCSPQUEUE")));
        
        ret = pub.storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, CertificateDataBean.CERT_ACTIVE, CertificateDataBean.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, null);
        assertFalse("Storing certificate to external ocsp publisher should fail.", ret);
        
        // Now this certificate fingerprint should be in the queue
    	Collection<PublisherQueueData> c = remote.getEntriesForPublisher(id);
    	assertEquals(1, c.size());
    	Iterator<PublisherQueueData> i = c.iterator();
    	PublisherQueueData d = i.next();
    	assertEquals(CertTools.getFingerprintAsString(cert), d.getFingerprint());
    }

    public void test99CleanUp() throws Exception {
    	Collection<PublisherQueueData> c = remote.getEntriesForPublisher(123456);
    	Iterator<PublisherQueueData> i = c.iterator();
    	while (i.hasNext()) {
    		PublisherQueueData d = i.next();
    		remote.removeQueueData(d.getPk());
    	}    

    	try {
    		pub.removePublisher(admin, "TESTEXTOCSPQUEUE");            
    	} catch (Exception pee) {
    		assertTrue(false);
    	}
    }
}
