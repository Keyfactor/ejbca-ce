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

package org.ejbca.core.model.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueProxySessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.junit.AfterClass;
import org.junit.Test;

/**
 * Tests the EndEntityInformation entity bean and some parts of EndEntityManagementSession.
 * 
 * @version $Id$
 */
public class PublisherQueueProcessTest {
    private static Logger log = Logger.getLogger(PublisherQueueProcessTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("PublisherQueueProcessTest"));

    private static byte[] testcert = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw" + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB" + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe" + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM" + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS" + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+" + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());

    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private final PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);

    /**
     * Add a new entry to the publisher queue and let the process service run,
     * with no publisher.
     * 
     */
    @Test
    public void test01PublishQueueProcessFail() throws Exception {
        publisherQueueSession.addQueueData(12345, PublisherConst.PUBLISH_TYPE_CERT, "TestPublishQueueProcessService12345", null,
                PublisherConst.STATUS_PENDING);
        Collection<PublisherQueueData> c = publisherQueueSession.getPendingEntriesForPublisher(12345);
        assertEquals(1, c.size());
        Iterator<PublisherQueueData> i = c.iterator();
        PublisherQueueData d = i.next();
        assertEquals(0, d.getTryCounter());

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

        serviceSession.addService(admin, "TestPublishQueueProcessService12345", config);
        // Try counter should be 0 before the service has run once
        d = checkEntriesForTest();
        assertEquals("Service should not have run and updated trycounter.", 0, d.getTryCounter());
        serviceSession.activateServiceTimer(admin, "TestPublishQueueProcessService12345");

        // The service will run...
        Thread.sleep(5000);
        d = checkEntriesForTest();
        if (d.getTryCounter() < 1) {
            // If the test is about to fail,with tryCounter < 1 here it might be that the CI environment is just slow, 
            // try to sleep another 5 seconds and try again
            log.info("d.getTryCounter is not 1 (but is "+d.getTryCounter()+"), perhaps the test environment is very slow, sleeping for another 5 seconds and trying again.");
            Thread.sleep(5000);            
            d = checkEntriesForTest();
        }
        assertTrue("Service should have run at least one time and updated trycounter, value is "+d.getTryCounter(), d.getTryCounter() > 0);
        assertEquals(PublisherConst.STATUS_PENDING, d.getPublishStatus());
    }

    private PublisherQueueData checkEntriesForTest() {
        PublisherQueueData d;
        // Now the publisher 12345 will not have existed so we should have
        // updated the publish entry's tryCounter
        Collection<PublisherQueueData> entries = publisherQueueSession.getEntriesByFingerprint("TestPublishQueueProcessService12345");
        assertEquals(1, entries.size());
        Iterator<PublisherQueueData> iter = entries.iterator();
        d = iter.next();
        return d;
    }

    /**
     * Add a new entry to the publisher queue and let the process service run,
     * with a publisher.
     * 
     */
    @Test
    public void test02PublishQueueProcessSuccess() throws Exception {
        // Add a Dummy publisher with Id 12345
        try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setKeepPublishedInQueue(true);
            publisher.setClassPath("org.ejbca.core.model.ca.publisher.DummyCustomPublisher");
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherProxySession.addPublisher(admin, "TestPublishQueueProcessService", publisher);
        } catch (PublisherExistsException pee) {
        }
        int publisherId = publisherProxySession.getPublisherId("TestPublishQueueProcessService");

        // We must add new entries to the queue, since we could not know the
        // publisherId before
        Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
        try {
            certificateStoreSession.storeCertificateRemote(admin, EJBTools.wrap(cert), "TestPublishQueueProcessService", null, CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY, 12345, 12345, "tag", new Date().getTime());
        } catch (Exception e) {
            // Perhaps the cert already exists
        }

        publisherQueueSession.addQueueData(publisherId, PublisherConst.PUBLISH_TYPE_CERT, CertTools.getFingerprintAsString(testcert), null,
                PublisherConst.STATUS_PENDING);
        Collection<PublisherQueueData> c = publisherQueueSession.getPendingEntriesForPublisher(publisherId);
        assertEquals(1, c.size());
        Iterator<PublisherQueueData> i = c.iterator();
        PublisherQueueData d = i.next();
        assertEquals(0, d.getTryCounter());

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

        serviceSession.addService(admin, "TestPublishQueueProcessService", config);
        serviceSession.activateServiceTimer(admin, "TestPublishQueueProcessService");

        // Let the service run and publish the entry
        Thread.sleep(5000);
        // Now the entry should be published
        // Now the publisher will not have existed so we should have updated the
        // publish entry's tryCounter
        c = publisherQueueSession.getEntriesByFingerprint(CertTools.getFingerprintAsString(testcert));
        assertEquals(1, c.size());
        i = c.iterator();
        d = i.next();
        assertEquals(0, d.getTryCounter());
        assertEquals(PublisherConst.STATUS_SUCCESS, d.getPublishStatus());
    }

    /**
     * Remove all data stored by JUnit tests
     * 
     */
    @AfterClass
    public static void cleanUp() throws Exception {
        PublisherQueueProxySessionRemote publisherQueueSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherQueueProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        InternalCertificateStoreSessionRemote internalCertStoreSession =EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        PublisherProxySessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        
        Collection<PublisherQueueData> c = publisherQueueSession.getEntriesByFingerprint("TestPublishQueueProcessService12345");
        Iterator<PublisherQueueData> i = c.iterator();
        while (i.hasNext()) {
            PublisherQueueData d = i.next();
            try {
                publisherQueueSession.removeQueueData(d.getPk());
            } catch (Exception pee) {
            }
        }
        c = publisherQueueSession.getEntriesByFingerprint(CertTools.getFingerprintAsString(testcert));
        i = c.iterator();
        while (i.hasNext()) {
            PublisherQueueData d = i.next();
            publisherQueueSession.removeQueueData(d.getPk());

        }

        // If the dummy cert was put in the database, remove it
        Certificate cert = CertTools.getCertfromByteArray(testcert, Certificate.class);
        internalCertStoreSession.removeCertificate(cert);

        serviceSession.removeService(admin, "TestPublishQueueProcessService12345");
        serviceSession.removeService(admin, "TestPublishQueueProcessService");

        publisherSession.removePublisherInternal(admin, "TestPublishQueueProcessService");

    }
}
