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

package org.ejbca.core.ejb.ca.caadmin;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.RenewCAWorker;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

/**
 * @version $Id$
 */
public class RenewCATest extends CaTestCase {
    private static final Logger log = Logger.getLogger(RenewCATest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RenewCATest"));

    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    /** Test renewal of a CA. */
    @Test
    public void test01renewCA() throws Exception {
        log.trace(">test01renewCA()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        // Sleep at least for one second so we are not so fast that we create a new cert with the same time
        Thread.sleep(2000);
        caAdminSession.renewCA(internalAdmin, info.getCAId(), false, null, false);
        X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        byte[] orgkey = orgcert.getPublicKey().getEncoded();
        byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue(Arrays.equals(orgkey, samekey));
        // The new certificate must have a validity greater than the old cert
        assertTrue("newcertsamekeys.getNotAfter: " + newcertsamekeys.getNotAfter() + " orgcert.getNotAfter: " + orgcert.getNotAfter(),
                newcertsamekeys.getNotAfter().after(orgcert.getNotAfter()));
        caAdminSession.renewCA(internalAdmin, info.getCAId(), true, null, false);
        X509CAInfo newinfo2 = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
        assertTrue(!orgcert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
        byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse(Arrays.equals(orgkey, newkey));
        log.trace("<test01renewCA()");
    }
    
    /** Test renewal of a subCA, using Renew CA Worker. */
    @Test
    public void testRenewSubCAWithRenewCAWorker() throws Exception {
        log.trace(">testRenewSubCAWithRenewCAWorker()");
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        final int cryptoTokenIdSubCa = CryptoTokenTestUtils.createCryptoTokenForCA(null, "foo123".toCharArray(), true, false, "TestSubCaRenew", "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken subCaToken = CaTestUtils.createCaToken(cryptoTokenIdSubCa, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        try {
            // Create sub CA to test renewal using Renew CA Worker
            X509CAInfo subCaInfo =  new X509CAInfo.X509CAInfoBuilder()
                    .setCaToken(subCaToken)
                    .setSubjectDn("CN=RenewSubCA")
                    .setName("TestSubCaRenew")
                    .setStatus(CAConstants.CA_ACTIVE)
                    .setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA)
                    .setEncodedValidity("20s")
                    .setSignedBy(info.getCAId())
                    .setCertificateChain(null)
                    .setUseUserStorage(false)
                    .setUseCertificateStorage(false)
                    .setCaSerialNumberOctetSize(20)
                    .build();
            if (caSession.existsCa("TestSubCaRenew")) {
                caSession.removeCA(internalAdmin, caSession.getCAInfo(internalAdmin, "TestSubCaRenew").getCAId());
            }
            caAdminSession.createCA(internalAdmin, subCaInfo);
            // Given
            X509CAInfo originaSubCalinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TestSubCaRenew");
            X509Certificate orgSubCacert = (X509Certificate) originaSubCalinfo.getCertificateChain().iterator().next();
            // Wait a little to get new expire time on new cert...
            Thread.sleep(2000);

            Map<Class<?>, Object> ejbs = new HashMap<Class<?>, Object>();
            ejbs.put(ServiceSessionLocal.class, serviceSession);
            final Integer subCaId = subCaInfo.getCAId();
            ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
            Properties properties = new Properties();
            Properties intervalProperties = new Properties();
            properties.setProperty(BaseWorker.PROP_CAIDSTOCHECK, subCaId.toString());
            properties.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, "8");
            properties.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
            properties.setProperty(RenewCAWorker.PROP_RENEWKEYS, "TRUE");
            intervalProperties.setProperty(PeriodicalInterval.PROP_VALUE, "2");
            intervalProperties.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
            serviceConfiguration.setWorkerProperties(properties);
            serviceConfiguration.setWorkerClassPath(RenewCAWorker.class.getName());
            serviceConfiguration.setActive(true);
            serviceConfiguration.setIntervalClassPath(PeriodicalInterval.class.getName());
            serviceConfiguration.setIntervalProperties(intervalProperties);
            serviceConfiguration.setActionClassPath(NoAction.class.getName());
            serviceConfiguration.setActionProperties(null);
            serviceSession.addService(internalAdmin, "RenewCaServiceTestService", serviceConfiguration);
            serviceSession.activateServiceTimer(internalAdmin, "RenewCaServiceTestService");
            // Let service run for a while...
            Thread.sleep(12000);
            X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TestSubCaRenew");
            X509Certificate newcertnewkeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
            // Then
            assertTrue("newcertnewkeys.getNotAfter: " + newcertnewkeys.getNotAfter() + " orgSubCacert.getNotAfter: " + orgSubCacert.getNotAfter(),
                    newcertnewkeys.getNotAfter().after(orgSubCacert.getNotAfter()));
            assertTrue(!orgSubCacert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
            byte[] orgkey = orgSubCacert.getPublicKey().getEncoded();
            byte[] newkey = newcertnewkeys.getPublicKey().getEncoded();
            assertFalse(Arrays.equals(orgkey, newkey));
        // Remove CA:s and Service...
        } finally {
            serviceSession.removeService(internalAdmin, "RenewCaServiceTestService");
            X509CAInfo caInfoSubCa = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TestSubCaRenew");
            if (caInfoSubCa != null) {
                CaTestUtils.removeCa(internalAdmin, caInfoSubCa);
            }
        }
        log.trace("<testRenewSubCAWithRenewCAWorker()");
    }
}
