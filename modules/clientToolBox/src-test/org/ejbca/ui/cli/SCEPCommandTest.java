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

import java.util.Collections;

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
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.ScepConfiguration;
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

/**
 * Run stress tests with ClientToolBax command SCEPTest
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SCEPCommandTest {

    @Rule
    public Timeout testTimeout = new Timeout(15_000); // per test case

    private final SCEPTest command  = new SCEPTest();
    private static String httpReqPath;
    private static final String SCEP_ALIAS = "SCEPCommandTestScepAlias";
    private static final String SCEP_CA = "SCEPCommandTestCA";
    private static final String CERTIFICATE_PROFILE_NAME = "SCEPCommandTestCP";
    private static final String END_ENTITY_PROFILE_NAME = "SCEPCommandTestEEP";
    private static final String DEFAULT_CA_DN = "CN=" + SCEP_CA;
    private static ScepConfiguration scepConfiguration;
    private static int certificateProfileId;
    private static X509CA x509ca;
    private static final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private static final AuthenticationToken authToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SCEPCommandTestTmp"));

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();

    @BeforeClass
    public static void setUp() throws Exception {

        ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        final String httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        final String httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        httpReqPath = "http://"+httpHost+":" + httpPort + "/ejbca";

        x509ca = CaTestUtils.createTestX509CA(DEFAULT_CA_DN, "foo123".toCharArray(), false);
        caSession.addCA(authToken, x509ca);
        CAInfo cainfo = caSession.getCAInfo(authToken, x509ca.getCAId());
        cainfo.setDoEnforceUniquePublicKeys(false);
        caSession.editCA(authToken, cainfo);

        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certificateProfile.setAllowKeyUsageOverride(true);
        certificateProfile.setAvailableCAs(Collections.singletonList(x509ca.getCAId()));
        certificateProfileId = certificateProfileSession.addCertificateProfile(authToken, CERTIFICATE_PROFILE_NAME, certificateProfile);

        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.addField(DnComponents.ORGANIZATION);
        endEntityProfile.addField(DnComponents.COUNTRY);
        endEntityProfile.addField(DnComponents.COMMONNAME);
        endEntityProfile.addField(DnComponents.DNSNAME);
        endEntityProfile.addField(DnComponents.IPADDRESS);
        endEntityProfile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setDefaultCA(x509ca.getCAId());
        endEntityProfileSession.addEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME, endEntityProfile);

        scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        scepConfiguration.addAlias(SCEP_ALIAS);
        scepConfiguration.setRAMode(SCEP_ALIAS, true);
        scepConfiguration.setIncludeCA(SCEP_ALIAS, false);
        scepConfiguration.setAllowLegacyDigestAlgorithm(SCEP_ALIAS, true);
        scepConfiguration.setRACertProfile(SCEP_ALIAS, CERTIFICATE_PROFILE_NAME);
        scepConfiguration.setRAEndEntityProfile(SCEP_ALIAS, END_ENTITY_PROFILE_NAME);
        scepConfiguration.setRADefaultCA(SCEP_ALIAS, x509ca.getName());

        globalConfigSession.saveConfiguration(authToken, scepConfiguration);
    }

    @AfterClass
    public static void tearDown() throws Exception {

        scepConfiguration.removeAlias(SCEP_ALIAS);
        globalConfigSession.saveConfiguration(authToken, scepConfiguration);

        final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        internalCertificateStoreSession.removeCertificatesByIssuer("CN=" + SCEP_CA);
        EndEntityManagementProxySessionRemote endEntityManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        endEntityManagementProxySession.deleteUsersByCertificateProfileId(certificateProfileId);
        endEntityProfileSession.removeEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME);
        certificateProfileSession.removeCertificateProfile(authToken, CERTIFICATE_PROFILE_NAME);
        CaTestUtils.removeCa(authToken, x509ca.getCAInfo());
    }


    // SCEP test: Start with just 3 calls since it may fail if started with a heavy load.
    @Test
    public void testCommand1SmallLoad() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 1;
        int numberOfTests = 3;
        String[] args = new String[]{"SCEPTest", httpReqPath + "/publicweb/apply/scep/" + SCEP_ALIAS + "/pkiclient.exe",
                SCEP_CA,
                numberOfThreads + ":" + numberOfTests};
        command.execute(args);
    }

    @Test
    public void testCommand2HeavyLoad() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 25;
        String waitTime ="1000";

        String[] args = new String[]{"SCEPTest", httpReqPath + "/publicweb/apply/scep/" + SCEP_ALIAS + "/pkiclient.exe",
                SCEP_CA,
                numberOfThreads + ":" + numberOfTests, waitTime};
        command.execute(args);
    }
}
