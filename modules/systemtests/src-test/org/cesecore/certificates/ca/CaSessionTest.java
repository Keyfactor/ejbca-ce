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



import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the CA session bean using soft CA tokens.
 * 
 * @version $Id$
 */
public class CaSessionTest extends RoleUsingTestCase {

    private static final String X509CADN = "CN=TEST";
    private static CA testx509ca;

    private static CaSessionTestBase testBase;

    @BeforeClass
    public static void setUpProviderAndCreateCA() throws Exception {
        CryptoProviderTools.installBCProvider();
        // Initialize role system
        setUpAuthTokenAndRole("CaSessionTestRoleInitialization");
        testx509ca = CaTestUtils.createTestX509CA(X509CADN, null, false);
        testBase = new CaSessionTestBase(testx509ca, null);            
    }
    
    @AfterClass
    public static void tearDownFinal() throws RoleNotFoundException, AuthorizationDeniedException {
        try {
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
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
        final int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
        testBase.addCAGenerateKeysLater(ca, cadn, tokenpwd.toCharArray());
        CryptoTokenTestUtils.removeCryptoToken(null, cryptoTokenId);
    }

    @Test
    public void addCAUseSessionBeanToGenerateKeys2() throws Exception {
        final String cadn = "CN=TEST GEN KEYS, O=CaSessionTest, C=SE";
        final String tokenpwd = "thisisatest";
        CA ca = CaTestUtils.createTestX509CAOptionalGenKeys(cadn, tokenpwd.toCharArray(), false, false);
        final int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
        testBase.addCAUseSessionBeanToGenerateKeys(ca, cadn, tokenpwd.toCharArray());
        CryptoTokenTestUtils.removeCryptoToken(null, cryptoTokenId);
    }

    @Test
    public void testExtendedCAService() throws Exception {
        CA ca = CaTestUtils.createTestX509CAOptionalGenKeys("CN=Test Extended CA service", "foo123".toCharArray(), false, false);
        final int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
        testBase.extendedCAServices(ca);
        CryptoTokenTestUtils.removeCryptoToken(null, cryptoTokenId);
    }

    @Test
    public void testAuthorization() throws Exception {
        testBase.authorization();
    }
}
