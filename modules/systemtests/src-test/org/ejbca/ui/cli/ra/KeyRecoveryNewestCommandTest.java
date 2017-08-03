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
package org.ejbca.ui.cli.ra;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Date;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class KeyRecoveryNewestCommandTest {

    private static final String TESTCLASS_NAME = KeyRecoveryNewestCommandTest.class.getSimpleName();
    private static final String END_ENTITY_SUBJECT_DN = "C=SE, O=PrimeKey, CN=" + TESTCLASS_NAME;

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);

    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            TESTCLASS_NAME));
    private final KeyRecoveryNewestCommand command = new KeyRecoveryNewestCommand();

    private static X509CA x509ca = null;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME);
        GlobalConfiguration configuration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        configuration.setEnableKeyRecovery(true);
        globalConfigurationSession.saveConfiguration(authenticationToken, configuration);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (x509ca != null) {
            final int caCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caCryptoTokenId);
            caSession.removeCA(authenticationToken, x509ca.getCAId());
        }
    }

    @Before
    public void setup() throws Exception {
        final EndEntityInformation userdata = new EndEntityInformation(TESTCLASS_NAME, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        endEntityManagementSession.addUser(authenticationToken, userdata, false);
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), userdata.getUsername(), userdata.getPassword());
        Certificate certificate = certificateCreateSession.createCertificate(authenticationToken, userdata, req, X509ResponseMessage.class, signSession.fetchCertGenParams())
                .getCertificate();
        if (null == endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)) {
            throw new RuntimeException("Could not create end entity.");
        }
        keyRecoverySession.addKeyRecoveryData(authenticationToken, EJBTools.wrap(certificate), TESTCLASS_NAME, EJBTools.wrap(keys));
    }

    @After
    public void teardown() throws Exception {
        if (null != endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, TESTCLASS_NAME);
        }
        keyRecoverySession.removeAllKeyRecoveryData(authenticationToken, TESTCLASS_NAME);
        for (Certificate certificate : EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(TESTCLASS_NAME))) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
    }

    @Test
    public void testKeyRecovery() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        assertTrue("End Entity was not marked for recovery.", keyRecoverySession.isUserMarked(TESTCLASS_NAME));
    }

}
