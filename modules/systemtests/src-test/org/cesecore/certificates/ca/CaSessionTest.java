/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;


import java.security.cert.X509Certificate;
import java.util.Collection;

import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.certificate.CertificateImplementationRegistry;
import com.keyfactor.util.certificate.x509.X509CertificateUtility;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the CA session bean using soft CA tokens.
 * 
 */
public class CaSessionTest extends RoleUsingTestCase {

    private static final String X509CADN = "CN=TEST";
    private static CA testx509ca;

    private static CaSessionTestBase testBase;

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken("CaSessionTest");
    
    @BeforeClass
    public static void setUpProviderAndCreateCA() throws Exception {
        CryptoProviderTools.installBCProvider();
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new X509CertificateUtility());
        testx509ca = CaTestUtils.createTestX509CA(X509CADN, null, false);
        testBase = new CaSessionTestBase(testx509ca, null);             
    }
    
    @AfterClass
    public static void tearDownFinal() throws RoleNotFoundException, AuthorizationDeniedException {
        if (testx509ca != null) {
            CaTestUtils.removeCa(alwaysAllowToken, testx509ca.getCAInfo());
        }
    }

    @Before
    public void setUp() throws Exception {
        testBase.setUp();
    }

    @After
    public void tearDown() throws Exception {
        testBase.tearDown();
    }

    @Test
    public void testAddRenameAndRemoveX509CA() throws Exception {
        testBase.addRenameAndRemoveX509CA();
    }

    @Test
    public void testAddAndGetCAWithDifferentCaid() throws Exception {
        testBase.addAndGetCAWithDifferentCaid();
    }

    @Test
    public void addCAGenerateKeysLater() throws Exception {
        final String cadn = "CN=TEST GEN KEYS, O=CaSessionTest, C=SE";
        final String tokenpwd = "thisisatest";
        CA ca = CaTestUtils.createTestX509CAOptionalGenKeys(cadn, tokenpwd.toCharArray(), false, false);
        try {
            // Store CA
            caSession.addCA(roleMgmgToken, ca);
            testBase.addCAGenerateKeysLater(ca, tokenpwd.toCharArray());
        } finally {
            // Clean up CA and crypto token
            CaTestUtils.removeCa(roleMgmgToken, ca.getCAInfo());
        }
    }

    @Test
    public void addCAUseSessionBeanToGenerateKeys2() throws Exception {
        final String cadn = "CN=TEST GEN KEYS, O=CaSessionTest, C=SE";
        final String tokenpwd = "thisisatest";
        CA ca = CaTestUtils.createTestX509CAOptionalGenKeys(cadn, tokenpwd.toCharArray(), false, false);
        try {
            // Store CA
            caSession.addCA(roleMgmgToken, ca);
            testBase.addCAUseSessionBeanToGenerateKeys(ca, tokenpwd.toCharArray());
        } finally {
            // Clean up CA and crypto token
            CaTestUtils.removeCa(roleMgmgToken, ca.getCAInfo());
        }
    }

    @Test
    public void testExtendedCAService() throws Exception {
        CA ca = CaTestUtils.createTestX509CAOptionalGenKeys("CN=Test Extended CA service", "foo123".toCharArray(), false, false);
        try {
            testBase.extendedCAServices(ca);
        } finally {
            if (ca != null) {
                CaTestUtils.removeCa(alwaysAllowToken, ca.getCAInfo());
            }
        }
    }

    @Test
    public void testAuthorization() throws Exception {
        testBase.authorization();
    }
    
    @Test
    public void testGetCaChain() throws Exception {        
        final String caDn = "CN=TestCAChain";
        final String caName = CertTools.getPartFromDN(caDn, "CN");
        CAInfo caInfo = null;
        try {
            final CA ca = CaTestUtils.createTestX509CAOptionalGenKeys(caDn, "foo123".toCharArray(), true, false);
            ca.setStatus(CAConstants.CA_ACTIVE);
            caSession.addCA(alwaysAllowToken, ca);
            caInfo = caSession.getCAInfo(alwaysAllowToken, caName); 
            
            // 1. Test get certificate chain.
            Collection<CertificateWrapper> certificates = caSession.getCaChain(alwaysAllowToken, caName);
            assertNotNull(certificates);
            assertEquals("The length if the CA certificate chain of a self signed CA should be 1.", 1, certificates.size());
            
            // 2. Test exception handling.
            // 2.1 Test with no authorization.
            final AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken((X509Certificate) certificates.iterator().next().getCertificate());
            try {
                certificates = caSession.getCaChain(adminTokenNoAuth, caName);
                fail("Get the CA certificate chain for an administrator with no authorization should throw an exception.");
            } catch(Exception e) {
                assertTrue("Get the CA certificate chain for a non existing CA should throw a CADoesntExistsException: " + e, 
                        e instanceof AuthorizationDeniedException);
            }
            // 2.2 Try to get CA chain for a non existing CA.
            try {
                certificates = caSession.getCaChain(alwaysAllowToken, caName + "-not-exists.");
                fail("Get the CA certificate chain for a non existing CA should throw an exception.");
            } catch(Exception e) {
                assertTrue("Get the CA certificate chain for a non existing CA should throw a CADoesntExistsException: " + e, 
                        e instanceof CADoesntExistsException);
            }
            // 2.3 Try to get the CA certificate chain for a CA with status =  CAConstants.CA_WAITING_CERTIFICATE_RESPONSE
            ca.setStatus(CAConstants.CA_WAITING_CERTIFICATE_RESPONSE);
            caSession.editCA(alwaysAllowToken, ca.getCAInfo());
            certificates = caSession.getCaChain(alwaysAllowToken, caName);
            assertEquals("Get the CA certificate chain for CA with status CAConstants.CA_WAITING_CERTIFICATE_RESPONSE should return an empty collection.", certificates.size(), 0);
        } finally {
            if (caInfo != null) {
                CaTestUtils.removeCa(alwaysAllowToken, caInfo);
            }
        }
    }
}
