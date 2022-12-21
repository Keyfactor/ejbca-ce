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
package org.ejbca.ui.cli;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementProxySessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.rules.Timeout;
import org.junit.runners.MethodSorters;

import java.util.Collections;

/**
 * Run stress tests with ClientToolBax command EjbcaWsRaCli
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EjbcaWsRaCliCommandTest {
    private final EjbcaWsRaCli command = new EjbcaWsRaCli();

    @Rule
    public Timeout testTimeout = new Timeout(90_000); // per test case

    private static final String CERTIFICATE_PROFILE_NAME = "EjbcaWsRaCliCommandTestCP";
    private static final String END_ENTITY_PROFILE_NAME = "EjbcaWsRaCliCommandTestEEP";
    private static final String CA_NAME = "EjbcaWsRaCliCommandTestCA";
    private static final String DEFAULT_CA_DN = "CN=" + CA_NAME;

    private static int certificateProfileId;
    private static X509CA x509ca;

    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private static final AuthenticationToken authToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWsRaCliCommandTestAT"));

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();

    @BeforeClass
    public static void setUp() throws Exception {

        x509ca = CaTestUtils.createTestX509CA(DEFAULT_CA_DN, "foo123".toCharArray(), false);
        caSession.addCA(authToken, x509ca);
        CAInfo cainfo = caSession.getCAInfo(authToken, x509ca.getCAId());
        cainfo.setDoEnforceUniquePublicKeys(false);
        caSession.editCA(authToken, cainfo);

        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfileId = certificateProfileSession.addCertificateProfile(authToken, CERTIFICATE_PROFILE_NAME, certificateProfile);

        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setDefaultCA(x509ca.getCAId());
        endEntityProfileSession.addEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME, endEntityProfile);


    }

    @AfterClass
    public static void tearDown() throws Exception {
        final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        internalCertificateStoreSession.removeCertificatesByIssuer(DEFAULT_CA_DN);
        EndEntityManagementProxySessionRemote endEntityManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        endEntityManagementProxySession.deleteUsersByCertificateProfileId(certificateProfileId);
        endEntityProfileSession.removeEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME);
        certificateProfileSession.removeCertificateProfile(authToken, CERTIFICATE_PROFILE_NAME);
        CaTestUtils.removeCa(authToken, x509ca.getCAInfo());
    }

    //WS: Start with just 3 calls since it may fail if started with a heavy load.
    @Test
    public void testCommand1SmallLoad() {
        exit.expectSystemExitWithStatus(0);

        int numberOfThreads = 1;
        int numberOfTests = 3;
        String waitTime ="2000";
        //EjbcaWsRaCli stress WSCA 1:3 2000 commonUserWS commonUserWS
        String[] args = new String[]{"EjbcaWsRaCli", "stress",
                CA_NAME,
                numberOfThreads + ":" + numberOfTests, waitTime, END_ENTITY_PROFILE_NAME, CERTIFICATE_PROFILE_NAME};
        command.execute(args);
    }

    @Test
    public void testCommand2HeavyLoad() {
        exit.expectSystemExitWithStatus(0);

        int numberOfThreads = 10;
        int numberOfTests = 100;
        String waitTime ="2000";
        //EjbcaWsRaCli stress WSCA 10:100 2000 commonUserWS commonUserWS
        String[] args = new String[]{"EjbcaWsRaCli", "stress",
                CA_NAME,
                numberOfThreads + ":" + numberOfTests, waitTime, END_ENTITY_PROFILE_NAME, CERTIFICATE_PROFILE_NAME};
        command.execute(args);
    }
}
