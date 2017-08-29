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
package org.ejbca.core.model.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test generating tokens
 * @version $Id$
 *
 */
public class GenerateTokenTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(GenerateTokenTest.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("GenerateTokenTest"));
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final KeyStoreCreateSessionRemote keyStoreCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private static final String TESTGENERATETOKENCA = "GENERATETOKENTEST_CA";
    private static final String GENERATETOKENTEST_EEP = "GENERATETOKENTEST_EEP";
    private static final String GENERATETOKENTEST_USERNAME = "GENERATETOKENTEST_USERNAME";

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();


        createTestCA(TESTGENERATETOKENCA);
        
        final int caId1 = caSession.getCAInfo(internalAdmin, TESTGENERATETOKENCA).getCAId();
        final Collection<Integer> availcas = new ArrayList<Integer>();
        availcas.add(caId1);
        final EndEntityProfile eeprofile = new EndEntityProfile();
        eeprofile.setAvailableCAs(availcas);
        endEntityProfileSession.addEndEntityProfile(internalAdmin, GENERATETOKENTEST_EEP, eeprofile);

    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();

        endEntityProfileSession.removeEndEntityProfile(internalAdmin, GENERATETOKENTEST_EEP);
        removeOldCa(TESTGENERATETOKENCA);
    }

    /**
     * Tests if token algorithm specified in endEntityInformation is enforced. If end entity is approved its algorithm
     * is approved as well. So if there is specified algorithm inside endEntityInformation.extendedInformation that one
     * should be enforced. 
     */
    @Test
    public void testEnforcingAlgorithmFromEndEntityInformation() throws Exception {
        log.trace(">testEnforcingAlgorithmFromEndEntityInformation");
        try {
            final int caId = caSession.getCAInfo(internalAdmin, TESTGENERATETOKENCA).getCAId();
            final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(GENERATETOKENTEST_EEP);

            EndEntityInformation eeinfo = new EndEntityInformation(GENERATETOKENTEST_USERNAME, "CN=GENERATETOKENTEST" + new Random().nextLong(), caId, "", null,
                    EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(), eeProfileId,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12,
                    SecConst.NO_HARDTOKENISSUER, null);
            eeinfo.setPassword("foo123");
            if (eeinfo.getExtendedInformation() == null) {
                eeinfo.setExtendedInformation(new ExtendedInformation());
            }
            //Setting up algorithm specification ECDSA_secp256r1 that is going to be enforced
            eeinfo.getExtendedInformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_ECDSA);
            eeinfo.getExtendedInformation().setKeyStoreAlgorithmSubType("prime256v1");

            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123");
            eeinfo = eeAccessSession.findUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            assertNotNull("Could not find test user", GENERATETOKENTEST_USERNAME);
            eeinfo.setPassword("foo123");

            //Providing separately algorithm RSA_1024 that is going to be overridden with ECDSA_secp256r1
            boolean createJKS = false;
            final byte[] keyStore = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123", caId, "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA, createJKS, false, true, false, eeProfileId);
            KeyStore ks = KeyStore.getInstance(createJKS?"JKS":"PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(new ByteArrayInputStream(keyStore), eeinfo.getPassword().toCharArray());
            Certificate cert = null;
            Enumeration<String> enumer = ks.aliases();
            while (enumer.hasMoreElements()) {
                String alias = enumer.nextElement();
                //The returned keystore will contain trusted certificate entry as well. We want to check key entry only.
                if(ks.isKeyEntry(alias)) {
                    cert = ks.getCertificate(alias);
                    assertNotNull("Unknown alias " + alias, cert); 
                }
            }
            PublicKey publicKey = cert.getPublicKey();
            assertEquals(AlgorithmConstants.KEYALGORITHM_ECDSA, AlgorithmTools.getKeyAlgorithm(publicKey));
            assertEquals("prime256v1", AlgorithmTools.getKeySpecification(publicKey));
            
        } finally {
            if (endEntityManagementSession.existsUser(GENERATETOKENTEST_USERNAME)) {
                endEntityManagementSession.deleteUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            }
            log.trace("<testEnforcingAlgorithmFromEndEntityInformation");
        }
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}

