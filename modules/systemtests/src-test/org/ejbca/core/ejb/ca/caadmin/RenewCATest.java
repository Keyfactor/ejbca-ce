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

    
    /** Test renewal of a CA using a different key algorithm. 
     *  Note: Can run these tests alone by using: ant test:runone -Dtest.runone=RenewCATest
    **/
    
    // Need these extra EJBs
    private final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);

    @Test
    public void test02renewCA_ChangeKeyAlg() throws Exception {
        log.trace(">test02renewCA_ChangeKeyAlg()");
        
        X509CAInfo info = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate orgcert = (X509Certificate) info.getCertificateChain().iterator().next();
        // Sleep at least for one second so we are not so fast that we create a new cert with the same time
        Thread.sleep(2000);
        
        // Prepare to renew CA but with an EC key
        
        // Get the CA's token
        final CAToken caToken = info.getCAToken();
        
        // The current Signing Algorithm should be RSA-based
        String sPreviousSigAlg = ((X509Certificate)orgcert).getSigAlgName();
        assertTrue("Current CA's Signature Algorithm should include RSA", sPreviousSigAlg.contains("RSA"));

        // Set the next key alias for the token
        String sNextKeyAlias = "TestEC";
        
        // Create an EC key. Need the CryptoTokeManagementSession for this
        cryptoTokenManagementSession.createKeyPair(internalAdmin, caToken.getCryptoTokenId(), sNextKeyAlias, com.keyfactor.util.keys.token.KeyGenParams.builder("prime256v1").build());

        // To get EJBCA to renew a CA with a different key algorithm, we need to:
        //   1. set up the signing algorithm in the CA's token to support EC, 
        //   2. ensure the certificate profile has an appropriate signature algorithm to support EC.
        
        // Set the signature algorithm of the token
        caToken.setSignatureAlgorithm( AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        
        // Need to set the Certificate Profile to use ECDSA based signature algorithm
        // Lets copy the current profile, change it, and save a new profile (as we can't edit the current profile)
        int iCP = info.getCertificateProfileId();
        org.cesecore.certificates.certificateprofile.CertificateProfile cpCA = certificateProfileSession.getCertificateProfile(iCP);
        cpCA.setSignatureAlgorithm( AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        iCP = certificateProfileSession.addCertificateProfile(internalAdmin, "TESTRENEWALWITHEC", cpCA);
        // Update the CA
        info.setCertificateProfileId(iCP);
        caSession.editCA(internalAdmin, info);

        // We are all set and now ready to renew the CA
        caAdminSession.renewCA(internalAdmin, info.getCAId(), sNextKeyAlias, null, /*CreateLinkCert*/true);

        // Remove the certificate profile we just created.
        certificateProfileSession.removeCertificateProfile(internalAdmin, "TESTRENEWALWITHEC");
        
        // Let check the CA's new certificate has the ECDSA based signing algorithm
        X509CAInfo newinfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, "TEST");
        X509Certificate newcert = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        String sNewSigAlg = ((X509Certificate)newcert).getSigAlgName();
        assertTrue( "Previous Signing Algorith was "+sPreviousSigAlg+" and new Signing Algorithm was "+sNewSigAlg+". Was expecting it to be ECDSA based.",
                sNewSigAlg.contains("ECDSA"));
       
        // Check the Link certificate was signed using the previous Signing Algorithm
        byte[] linkCertificateAfterRenewal1Bytes = caAdminSession.getLatestLinkCertificate(newinfo.getCAId());
        assertTrue("There is no available link certificate after CA renewal with EC key", linkCertificateAfterRenewal1Bytes != null);
        @SuppressWarnings("deprecation")
        X509Certificate linkCertificateAfterRenewal1 = (X509Certificate) com.keyfactor.util.CertTools.getCertfromByteArray(linkCertificateAfterRenewal1Bytes);
        assertTrue("The Link certificate should be signed by the CA's previous signing algorithm, not "+linkCertificateAfterRenewal1.getSigAlgName(),
                linkCertificateAfterRenewal1.getSigAlgName().equalsIgnoreCase(sPreviousSigAlg) );

        // Test done!
        log.trace("<test02renewCA_ChangeKeyAlg()");
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
