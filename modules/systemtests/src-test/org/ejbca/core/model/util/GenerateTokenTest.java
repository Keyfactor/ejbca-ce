package org.ejbca.core.model.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
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
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
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
    private static final EndEntityAuthenticationSessionRemote endEntityAuthSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityAuthenticationSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
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

            EndEntityInformation eeinfo = new EndEntityInformation(GENERATETOKENTEST_USERNAME, "CN=GENERATETOKENTEST" + new Random(), caId, "", null,
                    EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(), eeProfileId,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12,
                    SecConst.NO_HARDTOKENISSUER, null);
            eeinfo.setPassword("foo123");
            if (eeinfo.getExtendedinformation() == null) {
                eeinfo.setExtendedinformation(new ExtendedInformation());
            }
            //Setting up algorithm specification ECDSA_secp256r1 that is going to be enforced
            eeinfo.getExtendedinformation().setKeyStoreAlgorithmType(AlgorithmConstants.KEYALGORITHM_ECDSA);
            eeinfo.getExtendedinformation().setKeyStoreAlgorithmSubType("prime256v1");

            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123");
            eeinfo = eeAccessSession.findUser(internalAdmin, GENERATETOKENTEST_USERNAME);
            assertNotNull("Could not find test user", GENERATETOKENTEST_USERNAME);
            eeinfo.setPassword("foo123");

            final GenerateToken tgen1 = new GenerateToken(endEntityAuthSession, eeAccessSession, endEntityManagementSession, caSession,
                    keyRecoverySession, signSession);
            //Providing separately algorithm RSA_1024 that is going to be overriden with ECDSA_secp236r1
            final KeyStore keyStore = tgen1.generateOrKeyRecoverToken(internalAdmin, GENERATETOKENTEST_USERNAME, "foo123", caId, "1024",
                    AlgorithmConstants.KEYALGORITHM_RSA, false, false, true, false, eeProfileId);
            
            Certificate cert = keyStore.getCertificate(keyStore.aliases().nextElement());
            assertNotNull("Unknown alias " + keyStore.aliases().nextElement(), cert);
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

