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
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
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

import java.io.File;
import java.io.FileOutputStream;
import java.security.cert.Certificate;
import java.util.Collections;

/**
 * Run stress tests with ClientToolBax command CMPTest
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CmpTestCommandTest {
    private final CMPTest command = new CMPTest();

    @Rule
    public Timeout testTimeout = new Timeout(30_000); // per test case

    private static final String CERTIFICATE_PROFILE_NAME = "CmpTestCommandTestCP";
    private static final String END_ENTITY_PROFILE_NAME = "CmpTestCommandTestEEP";
    private static final String CA_NAME = "CmpTestCommandTestCA";
    private static final String DEFAULT_CA_DN = "CN=" + CA_NAME;
    private static final String CMP_ALIAS = "CmpTestCommandTestCmpAlias";

    private static int certificateProfileId;
    private static X509CA x509ca;
    private static File caCertificateFile;
    private static CmpConfiguration cmpConfiguration;
    private static String httpHost;

    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final AuthenticationToken authToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpTestCommandTestAT"));

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();

    @BeforeClass
    public static void setUp() throws Exception {
        ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));

        x509ca = CaTestUtils.createTestX509CA(DEFAULT_CA_DN, "foo123".toCharArray(), false);
        caSession.addCA(authToken, x509ca);
        Certificate caCertificate = x509ca.getCACertificate();
        CAInfo cainfo = caSession.getCAInfo(authToken, x509ca.getCAId());
        cainfo.setDoEnforceUniquePublicKeys(false);
        caSession.editCA(authToken, cainfo);
        caCertificateFile = File.createTempFile("tmp", ".pem");
        try (FileOutputStream fileOutputStream = new FileOutputStream(caCertificateFile)) {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Collections.singletonList(caCertificate)));
        }

        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowDNOverride(true);
        certificateProfile.setAvailableCAs(Collections.singletonList(x509ca.getCAId()));
        certificateProfileId = certificateProfileSession.addCertificateProfile(authToken, CERTIFICATE_PROFILE_NAME, certificateProfile);

        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setDefaultCA(x509ca.getCAId());
        int endEntityProfileId = endEntityProfileSession.addEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME, endEntityProfile);

        cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        cmpConfiguration.addAlias(CMP_ALIAS);
        cmpConfiguration.setRAMode(CMP_ALIAS, true);
        cmpConfiguration.setAuthenticationModule(CMP_ALIAS, CmpConfiguration.AUTHMODULE_HMAC);
        cmpConfiguration.setAuthenticationParameters(CMP_ALIAS, "password");
        cmpConfiguration.setAllowRAVerifyPOPO(CMP_ALIAS, true);
        cmpConfiguration.setResponseProtection(CMP_ALIAS, "signature");
        cmpConfiguration.setRACAName(CMP_ALIAS, CA_NAME);
        cmpConfiguration.setRACertProfile(CMP_ALIAS, CERTIFICATE_PROFILE_NAME);
        cmpConfiguration.setRAEEProfile(CMP_ALIAS, String.valueOf(endEntityProfileId));
        globalConfigSession.saveConfiguration(authToken, cmpConfiguration);
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
        FileTools.delete(caCertificateFile);
        cmpConfiguration.removeAlias(CMP_ALIAS);
        globalConfigSession.saveConfiguration(authToken, cmpConfiguration);
    }

    @Test
    //CMP RA: Start with just 3 calls since it may fail if started with a heavy load
    public void testCommand1SmallLoad() {
        exit.expectSystemExitWithStatus(0);
        //CMPTest ca CMPCA.cacert.pem 1:3 1000 testRA
        int numberOfThreads = 1;
        int numberOfTests = 3;
        String waitTime ="1000";
        String[] args = new String[]{"CMPTest", httpHost,
                caCertificateFile.getAbsolutePath(),
                numberOfThreads + ":" + numberOfTests, waitTime, CMP_ALIAS};
        command.execute(args);
    }

    @Test
    public void testCommand2HeavyLoad() {
        exit.expectSystemExitWithStatus(0);
        //CMPTest ca CMPCA.cacert.pem 10:100 1000 testRA
        int numberOfThreads = 10;
        int numberOfTests = 100;
        String waitTime ="1000";
        String[] args = new String[]{"CMPTest", httpHost,
                caCertificateFile.getAbsolutePath(),
                numberOfThreads + ":" + numberOfTests, waitTime, CMP_ALIAS};
        command.execute(args);
    }
}
