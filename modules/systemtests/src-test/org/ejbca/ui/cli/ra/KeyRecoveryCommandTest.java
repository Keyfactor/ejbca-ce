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

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
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
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
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

import static org.junit.Assert.assertTrue;

/**
 * @version $Id$
 *
 */
public class KeyRecoveryCommandTest {

    private static final String TESTCLASS_NAME = KeyRecoveryCommandTest.class.getSimpleName();
    private static final String END_ENTITY_SUBJECT_DN = "C=SE, O=PrimeKey, CN=" + TESTCLASS_NAME;

    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "KeyRecoveryCommandTest"));
    private final KeyRecoveryCommand command = new KeyRecoveryCommand();

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
            CaTestUtils.removeCa(authenticationToken, x509ca.getCAInfo());
        }
    }

    @Before
    public void setup() throws Exception {
        final EndEntityInformation userdata = new EndEntityInformation(TESTCLASS_NAME, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
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
        X509Certificate userCertificate = certificateStoreSession.findLatestX509CertificateBySubject(END_ENTITY_SUBJECT_DN);
        String[] args = new String[] { CertTools.getSerialNumberAsString(userCertificate), x509ca.getSubjectDN() };
        command.execute(args);
        assertTrue("End Entity was not marked for recovery.", keyRecoverySession.isUserMarked(TESTCLASS_NAME));
    }

}
