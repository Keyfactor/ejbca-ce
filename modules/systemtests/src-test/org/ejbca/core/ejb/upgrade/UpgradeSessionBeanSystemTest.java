/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.upgrade;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.certificates.certificatetransparency.PolicyBreakpoint;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.GlobalCaConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.GlobalCtConfiguration;
import org.cesecore.config.GlobalEndEntityProfileConfiguration;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.InvalidConfigurationException;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspNonExistingBehavior;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationCheckerConfiguration;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.unidfnr.UnidFnrHandlerMock;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * System tests for the upgrade session bean. 
 */
@SuppressWarnings("deprecation")
public class UpgradeSessionBeanSystemTest {

    private static final String TESTCLASS = UpgradeSessionBeanSystemTest.class.getSimpleName();
    private static final String TEST_ENDENTITY1 = UpgradeSessionBeanSystemTest.class.getSimpleName() + "1";
    private static final String TEST_ENDENTITY2 = UpgradeSessionBeanSystemTest.class.getSimpleName() + "2";
    private static final String TESTCA = UpgradeSessionBeanSystemTest.class.getSimpleName() + "CA";
    
    private static CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private GlobalConfigurationProxySessionRemote globalConfigurationProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private UpgradeSessionRemote upgradeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalKeyBindingMgmtSessionRemote internalKeyBindingSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        
    private static AuthenticationToken alwaysAllowtoken = new TestAlwaysAllowLocalAuthenticationToken("UpgradeSessionBeanSystemTest");
    
    private AvailableCustomCertificateExtensionsConfiguration cceConfigBackup;
    private AvailableExtendedKeyUsagesConfiguration ekuConfigBackup; 
    private GlobalUpgradeConfiguration gucBackup;
    private GlobalConfiguration gcBackup;
    /** Dummy CA to use where a CA reference is required */
    private static CAInfo testCaInfo;

    @BeforeClass
    public static void beforeClass() throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, CAExistsException, InvalidAlgorithmException, AuthorizationDeniedException, CertIOException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // Clean up from previous aborted tests
        CaTestUtils.removeCa(alwaysAllowtoken, "NoActions", "NoActions");
        CaTestUtils.removeCa(alwaysAllowtoken, "TwoApprovals", "TwoApprovals");
        CaTestUtils.removeCa(alwaysAllowtoken, "ThreeApprovals", "ThreeApprovals");
        // Add dummy CA
        CaTestUtils.removeCa(alwaysAllowtoken, TESTCA, TESTCA);
        final X509CA ca = CaTestUtils.createTestX509CA("CN=" + TESTCA, "foo123".toCharArray(), false);
        caAdminSession.createCA(alwaysAllowtoken, ca.getCAInfo());
        testCaInfo = caSession.getCAInfo(alwaysAllowtoken, TESTCA);
    }
    
    @AfterClass
    public static void afterClass() throws AuthorizationDeniedException {
        CaTestUtils.removeCa(alwaysAllowtoken, testCaInfo); 
    }
    
    @Before
    public void setUp() {
        cceConfigBackup = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        ekuConfigBackup = (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
        gucBackup = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        gcBackup = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }
    
    @After
    public void tearDown() throws Exception {
        globalConfigSession.saveConfiguration(alwaysAllowtoken, cceConfigBackup);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, ekuConfigBackup);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, gucBackup);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, gcBackup);
    }
        
   /** Basic test that Statedump defaults to being disabled. The actual upgrade is to be tested manually in ECAQA-82 */
   @SuppressWarnings("unchecked")
   @Test
   public void testStatedumpLockdown() {
       final GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
       
       final Map<Object,Object> data = (Map<Object,Object>) globalConfig.saveData(); // returns a copy that we can modify
       data.remove("statedump_lockdown");
       globalConfig.loadData(data);
       assertTrue("Statedump should be locked down in the default state", globalConfig.getStatedumpLockedDown());
   }
   @Test
   public void testVersionUtil() throws NoSuchMethodException, SecurityException, IllegalAccessException, InvocationTargetException, IllegalArgumentException, InstantiationException {
       assertTrue("Version util did not parse correctly.", isLesserThan("1", "2"));
       assertFalse("Version util did not parse correctly.", isLesserThan("2", "1"));
       assertTrue("Version util did not parse correctly.", isLesserThan("1.0", "2.0"));
       assertTrue("Version util did not parse correctly.", isLesserThan("2.0", "2.1"));
       assertFalse("Version util did not parse correctly.", isLesserThan("1.0", "1.0"));
       assertTrue("Version util did not parse correctly.", isLesserThan("2.0.0", "2.1"));
       assertTrue("Version util did not parse correctly.", isLesserThan("2.1", "2.1.1"));
   }
   
    private boolean isLesserThan(String firstVersion, String secondVersion) throws IllegalAccessException, InvocationTargetException,
            NoSuchMethodException, SecurityException, IllegalArgumentException, InstantiationException {
        Method upgradeMethod = UpgradeSessionBean.class.getDeclaredMethod("isLesserThan", String.class, String.class);
        upgradeMethod.setAccessible(true);
        return (Boolean) upgradeMethod.invoke(UpgradeSessionBean.class.newInstance(), firstVersion, secondVersion);
    }

    @Test
    public void testUpgradeOcspKeyBindingWithNoArchiveCutoffConfigured730() throws Exception {
        try {
            final int cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token");
            final int internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(alwaysAllowtoken, cryptoTokenId,
                    OcspKeyBinding.IMPLEMENTATION_ALIAS, "Upgrade730 OCSP Responder",
                    "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

            final GlobalUpgradeConfiguration globalUpgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            globalUpgradeConfiguration.setUpgradedFromVersion("7.2.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalUpgradeConfiguration);
            cesecoreConfigSession.setConfigurationValue("ocsp.expiredcert.retentionperiod", null);
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "7.2.0", /* post upgrade? */ false);
            final InternalKeyBindingInfo ocspResponder = internalKeyBindingSession.getInternalKeyBindingInfo(alwaysAllowtoken, internalKeyBindingId);
            Assert.assertTrue(
                    "OCSP key binding should not contain an archive cutoff extension when upgrading without 'ocsp.expiredcert.retentionperiod' configured.",
                    !ocspResponder.getOcspExtensions().contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId()));
        } finally {
            OcspTestUtils.removeInternalKeyBinding(alwaysAllowtoken, "Upgrade730 OCSP Responder");
            CryptoTokenTestUtils.removeCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token");
        }
    }

    @Test
    public void testUpgradeOcspKeyBindingWithArchiveCutoffDisabled730() throws Exception {
        try {
            final int cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token");
            final int internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(alwaysAllowtoken, cryptoTokenId,
                    OcspKeyBinding.IMPLEMENTATION_ALIAS, "Upgrade730 OCSP Responder", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

            final GlobalUpgradeConfiguration globalUpgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            globalUpgradeConfiguration.setUpgradedFromVersion("7.2.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalUpgradeConfiguration);
            cesecoreConfigSession.setConfigurationValue("ocsp.expiredcert.retentionperiod", "-1");
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "7.2.0", /* post upgrade? */ false);
            final InternalKeyBindingInfo ocspResponder = internalKeyBindingSession.getInternalKeyBindingInfo(alwaysAllowtoken, internalKeyBindingId);
            Assert.assertTrue("OCSP key binding should not contain an archive cutoff extension when 'ocsp.expiredcert.retentionperiod=-1'.",
                    !ocspResponder.getOcspExtensions().contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId()));
        } finally {
            OcspTestUtils.removeInternalKeyBinding(alwaysAllowtoken, "Upgrade730 OCSP Responder");
            CryptoTokenTestUtils.removeCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token");
        }
    }

    @Test
    public void testUpgradeOcspKeyBindingsWithArchiveCutoffEnabled730() throws Exception {
        try {
            final int cryptoTokenId1 = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token 1");
            final int internalKeyBindingId1 = OcspTestUtils.createInternalKeyBinding(alwaysAllowtoken, cryptoTokenId1,
                    OcspKeyBinding.IMPLEMENTATION_ALIAS, "Upgrade730 OCSP Responder 1", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            final int cryptoTokenId2 = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token 2");
            final int internalKeyBindingId2 = OcspTestUtils.createInternalKeyBinding(alwaysAllowtoken, cryptoTokenId2,
                    OcspKeyBinding.IMPLEMENTATION_ALIAS, "Upgrade730 OCSP Responder 2", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

            final GlobalUpgradeConfiguration globalUpgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            globalUpgradeConfiguration.setUpgradedFromVersion("7.2.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalUpgradeConfiguration);
            cesecoreConfigSession.setConfigurationValue("ocsp.expiredcert.retentionperiod", /* 10 years */ "315360000");
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "7.2.0", /* post upgrade? */ false);

            final InternalKeyBindingInfo ocspResponder1 = internalKeyBindingSession.getInternalKeyBindingInfo(alwaysAllowtoken,
                    internalKeyBindingId1);
            final InternalKeyBindingInfo ocspResponder2 = internalKeyBindingSession.getInternalKeyBindingInfo(alwaysAllowtoken,
                    internalKeyBindingId2);
            Assert.assertTrue("The 1st OCSP key binding is missing an archive cutoff extension.",
                    ocspResponder1.getOcspExtensions().contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId()));
            Assert.assertTrue("The 2nd OCSP key binding is missing an archive cutoff extension.",
                    ocspResponder1.getOcspExtensions().contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId()));
            Assert.assertEquals("The 1st OCSP key binding should have the retention period set to 10 years.", "10y",
                    ocspResponder1.getRetentionPeriod());
            Assert.assertEquals("The 2nd OCSP key binding should have the retention period set to 10 years.", "10y",
                    ocspResponder2.getRetentionPeriod());
        } finally {
            OcspTestUtils.removeInternalKeyBinding(alwaysAllowtoken, "Upgrade730 OCSP Responder 1");
            CryptoTokenTestUtils.removeCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token 1");
            OcspTestUtils.removeInternalKeyBinding(alwaysAllowtoken, "Upgrade730 OCSP Responder 2");
            CryptoTokenTestUtils.removeCryptoToken(alwaysAllowtoken, "Upgrade730 Crypto Token 2");
        }
    }

    @Test
    public void testRemoveStaleAccessRules730() throws Exception {
        Role persistedRole = null;
        try {
            final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            // Disable key recovery and add a stale access rule
            globalConfiguration.setEnableKeyRecovery(false);
            final HashMap<String, Boolean> accessRules = new HashMap<>();
            accessRules.put(AccessRulesConstants.REGULAR_KEYRECOVERY, Role.STATE_ALLOW);
            final Role role = new Role(null, "testRemoveStaleAccessRules730", accessRules);
            persistedRole = roleSession.persistRole(alwaysAllowtoken, role);
            final GlobalUpgradeConfiguration globalUpgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            globalUpgradeConfiguration.setUpgradedFromVersion("7.2.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalUpgradeConfiguration);
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "7.2.0", /* post upgrade? */ false);
            final Role roleAfterUpgrade = roleSession.getRole(alwaysAllowtoken, persistedRole.getRoleId());
            assertTrue("Stale access rule was not removed.",
                    !roleAfterUpgrade.getAccessRules().containsKey(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY)));
        } finally {
            if (persistedRole != null) {
                roleSession.deleteRoleIdempotent(alwaysAllowtoken, persistedRole.getRoleId());
            }
        }
    }

    @Test
    public void testExternalScriptsSetting() throws AuthorizationDeniedException, PublisherExistsException, PublisherException {
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        boolean savedEnableExternalScripts = gc.getEnableExternalScripts();
        gc.setEnableExternalScripts(true);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, gc);
        
        try {
            final CustomPublisherContainer cpc = new CustomPublisherContainer();
            cpc.setClassPath(GeneralPurposeCustomPublisher.class.getName());
            cpc.setPropertyData(GeneralPurposeCustomPublisher.CRL_EXTERNAL_COMMAND_PROPERTY_NAME + "=/opt/example.sh");
            cpc.setDescription("Description ABC 123");
            cpc.setName(TESTCLASS);
            publisherSession.addPublisher(alwaysAllowtoken, TESTCLASS, cpc);
            
            GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedFromVersion("6.10.1");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            upgradeSession.upgrade(null, "6.11.0", false);
            
            globalConfigSession.flushConfigurationCache(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            gc = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            assertTrue("External scripts should have been enabled when a General Purpose Custom Publisher is present.", gc.getEnableExternalScripts());
        } finally {
            publisherProxySession.removePublisherInternal(alwaysAllowtoken, TESTCLASS);
            
            gc = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            gc.setEnableExternalScripts(savedEnableExternalScripts);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, gc);
        }
    }

    @Test
    public void testSecondsGranularityInUserDataBeforePostUpgrade() throws Exception {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.1.0");
        guc.setPostUpgradedToVersion("7.1.0");
        guc.setCustomCertificateWithSecondsGranularity(false);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        try {
            // End Entities created before post upgrade should not have seconds granularity in start/end time fields
            endEntityManagementSession.addUser(alwaysAllowtoken, makeEndEntityInfo(TEST_ENDENTITY1, "2019-02-03 04:05:06", "2019-12-31 23:59:59"), false);
            endEntityManagementSession.addUser(alwaysAllowtoken, makeEndEntityInfo(TEST_ENDENTITY2, null, null), false);
            endEntityManagementSession.changeUser(alwaysAllowtoken, makeEndEntityInfo(TEST_ENDENTITY2, "2019-11-13 14:15:16", "2019-12-31 23:59:59"), false);
            ExtendedInformation addedInfo = endEntityAccessSession.findUser(alwaysAllowtoken, TEST_ENDENTITY1).getExtendedInformation();
            ExtendedInformation changedInfo = endEntityAccessSession.findUser(alwaysAllowtoken, TEST_ENDENTITY2).getExtendedInformation();
            assertEquals("User added before post-upgrade should NOT have seconds in start time.", "2019-02-03 04:05", addedInfo.getCertificateStartTime());
            assertEquals("User added before post-upgrade should NOT have seconds in end time.", "2019-12-31 23:59", addedInfo.getCertificateEndTime());
            assertEquals("User changed before post-upgrade should NOT have seconds in start time.", "2019-11-13 14:15", changedInfo.getCertificateStartTime());
            assertEquals("User changed before post-upgrade should NOT have seconds in end time.", "2019-12-31 23:59", changedInfo.getCertificateEndTime());
        } finally {
            deleteEndEntity(TEST_ENDENTITY1);
            deleteEndEntity(TEST_ENDENTITY2);
        }
    }

    @Test
    public void testSecondsGranularityInUserDataAfterPostUpgrade() throws Exception {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.1.0");
        guc.setPostUpgradedToVersion("7.1.0");
        guc.setCustomCertificateWithSecondsGranularity(false);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        upgradeSession.upgrade(null, "7.1.0", true);
        guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        assertTrue("isCustomCertificateValidityWithSecondsGranularity should be true after post-upgrade", guc.isCustomCertificateValidityWithSecondsGranularity());
        try {
            // End Entities created before post upgrade should not have seconds granularity in start/end time fields
            endEntityManagementSession.addUser(alwaysAllowtoken, makeEndEntityInfo(TEST_ENDENTITY1, "2019-02-03 04:05:06", "2019-12-31 23:59:59"), false);
            endEntityManagementSession.addUser(alwaysAllowtoken, makeEndEntityInfo(TEST_ENDENTITY2, null, null), false);
            endEntityManagementSession.changeUser(alwaysAllowtoken, makeEndEntityInfo(TEST_ENDENTITY2, "2019-11-13 14:15:16", "2019-12-31 23:59:59"), false);
            ExtendedInformation addedInfo = endEntityAccessSession.findUser(alwaysAllowtoken, TEST_ENDENTITY1).getExtendedInformation();
            ExtendedInformation changedInfo = endEntityAccessSession.findUser(alwaysAllowtoken, TEST_ENDENTITY2).getExtendedInformation();
            assertEquals("User added after post-upgrade SHOULD HAVE seconds in start time.", "2019-02-03 04:05:06", addedInfo.getCertificateStartTime());
            assertEquals("User added after post-upgrade SHOULD HAVE seconds in end time.", "2019-12-31 23:59:59", addedInfo.getCertificateEndTime());
            assertEquals("User changed after post-upgrade SHOULD HAVE seconds in start time.", "2019-11-13 14:15:16", changedInfo.getCertificateStartTime());
            assertEquals("User changed after post-upgrade SHOULD HAVE seconds in end time.", "2019-12-31 23:59:59", changedInfo.getCertificateEndTime());
        } finally {
            deleteEndEntity(TEST_ENDENTITY1);
            deleteEndEntity(TEST_ENDENTITY2);
        }
    }
    
    /**
     * Tests the removal of unid configuration from CMP aliases during upgrade. Testing that UnidFnr functions before and after upgrade is done in CmpRAUnidSystemTest
     */
    @Test
    public void testUpgradeTo740RemoveUnifFnrConfiguration() throws AuthorizationDeniedException {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.3.0");
        guc.setPostUpgradedToVersion("7.3.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        //Add unid configuration to CMP
        final String alias = "testUpgradeTo740RemoveUnifFnrConfiguration";
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        cmpConfiguration.addAlias(alias);
        cmpConfiguration.setCertReqHandlerClass(alias, UnidFnrHandlerMock.class.getName());
        globalConfigSession.saveConfiguration(alwaysAllowtoken, cmpConfiguration);
        upgradeSession.upgrade(null, "7.3.0", true);
        //UnidFnr information should be removed from CMP configuration post upgrade
        CmpConfiguration upgradedCmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertNull("CertReqHandler should have been removed from CMP configuration during upgrade", upgradedCmpConfiguration.getCertReqHandlerClass(alias));

        
    }

    /** Tests addition of new access rules for Public Access RA added in 7.10.0 */
    @Test
    public void testUpgradeAccessRules7100() throws AuthorizationDeniedException, RoleExistsException {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.9.0");
        guc.setPostUpgradedToVersion("7.9.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        // Add role
        Role role = new Role("UpgradeTestNamespace", "Role", Arrays.asList(AccessRulesConstants.REGULAR_CREATECERTIFICATE + "/"), Collections.emptyList());
        role.normalizeAccessRules();
        roleSession.deleteRoleIdempotent(alwaysAllowtoken, "UpgradeTestNamespace", "Role");
        try {
            roleSession.persistRole(alwaysAllowtoken, role);
            // Perform upgrade
            upgradeSession.upgrade(null, "7.9.0", false);
            // Check role
            role = roleSession.getRole(alwaysAllowtoken, "UpgradeTestNamespace", "Role");
            assertEquals("New access rule was not added", Boolean.TRUE, role.getAccessRules().get(AccessRulesConstants.REGULAR_USEUSERNAME + "/"));
            assertEquals("New access rule was not added", Boolean.TRUE, role.getAccessRules().get(AccessRulesConstants.REGULAR_USEAPPROVALREQUESTID + "/"));
        } finally {
            roleSession.deleteRoleIdempotent(alwaysAllowtoken, "UpgradeTestNamespace", "Role");
        }
    }

    @Test
    public void testUpgradeCmpVendorCaConfiguration7110() throws AuthorizationDeniedException {
        // Set previous upgraded to 7.10
        final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.10.0");
        guc.setPostUpgradedToVersion("7.10.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        String cmpAlias = "testUpgradeVendorCaCmp";
        String cmpAliasNoVendors = "testUpgradeVendorCACmpNoVendors";
        CmpConfiguration cmpConfiguration =
                (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        try {
            // One vendor CA
            cmpConfiguration.addAlias(cmpAlias);
            String caName = testCaInfo.getName();
            // testCa should be converted to the new ID format, BogusCA should disappear during upgrade since no CA with that name exists
            cmpConfiguration.setValue(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCA, caName + ";BogusCA", cmpAlias);
            assertEquals("Vendor CAs should not be stored as IDs yet (default value is empty string)",
                    cmpConfiguration.getValue(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCAIDS, cmpAlias), "");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, cmpConfiguration);
            upgradeSession.upgrade(null, "7.10.0", false);
            // Update cmp config
            cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            String vendorIdString = cmpConfiguration.getValue(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCAIDS, cmpAlias);
            assertEquals("Vendor CAs should now be stored with the new ID format",
                    vendorIdString, String.valueOf(testCaInfo.getCAId()));
            assertEquals("Vendors with the old name format should still be present",
                    cmpConfiguration.getValue(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCA, cmpAlias),
                    caName + ";BogusCA");
            upgradeSession.upgrade(null, "7.10.0", true);
            // Update cmp config
            cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            assertNull("After running post-upgrade vendor CAs with the old format should be gone",
                    cmpConfiguration.getValue(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCA, cmpAlias));
            // No vendor CAs
            cmpConfiguration.addAlias(cmpAliasNoVendors);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, cmpConfiguration);
            assertNull("No vendor CAs should be stored",
                    cmpConfiguration.getValue(cmpAliasNoVendors + "." + CmpConfiguration.CONFIG_VENDORCA, cmpAliasNoVendors));
            assertEquals("Vendor CA IDs should be initialized but empty",
                    "",
                    cmpConfiguration.getValue(cmpAliasNoVendors + "." + CmpConfiguration.CONFIG_VENDORCAIDS, cmpAliasNoVendors));
            upgradeSession.upgrade(null, "7.10.0", false);
            // Update cmp config
            cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            assertNull("Still, no vendor CAs should be stored",
                    cmpConfiguration.getValue(cmpAliasNoVendors + "." + CmpConfiguration.CONFIG_VENDORCA, cmpAliasNoVendors));
            assertEquals("Vendor CA IDs should be initialized but empty",
                    "",
                    cmpConfiguration.getValue(cmpAliasNoVendors + "." + CmpConfiguration.CONFIG_VENDORCAIDS, cmpAliasNoVendors));
        } finally {
            cmpConfiguration.removeAlias(cmpAlias);
            cmpConfiguration.removeAlias(cmpAliasNoVendors);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, cmpConfiguration);
        }
    }

    @Test
    public void testUpgradeEstVendorCaConfiguration7110() throws AuthorizationDeniedException {
        // Set previous upgraded to 7.10
        final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.10.0");
        guc.setPostUpgradedToVersion("7.10.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        String estAlias = "testUpgradeVendorCaEst";
        String estAliasNoVendors = "testUpgradeVendorCaEstNoVendors";
        EstConfiguration estConfiguration =
                (EstConfiguration) globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        try {
            // One vendor CA
            estConfiguration.addAlias(estAlias);
            String caName = testCaInfo.getName();
            // testCa should be converted to the new ID format, BogusCA should disappear during upgrade since no CA with that name exists
            estConfiguration.setValue(estAlias + "." + EstConfiguration.CONFIG_VENDORCA, caName + ";BogusCA", estAlias);
            assertEquals("Vendor CAs should not be stored as IDs yet (default value is empty string)",
                    estConfiguration.getValue(estAlias + "." + EstConfiguration.CONFIG_VENDORCAIDS, estAlias), "");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, estConfiguration);
            upgradeSession.upgrade(null, "7.10.0", false);
            // Update est config
            estConfiguration = (EstConfiguration) globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            String vendorIdString = estConfiguration.getValue(estAlias + "." + EstConfiguration.CONFIG_VENDORCAIDS, estAlias);
            assertEquals("Vendor CAs should now be stored with the new ID format",
                    vendorIdString, String.valueOf(testCaInfo.getCAId()));
            assertEquals("Vendors with the old name format should still be present",
                    estConfiguration.getValue(estAlias + "." + EstConfiguration.CONFIG_VENDORCA, estAlias),
                    caName + ";BogusCA");
            upgradeSession.upgrade(null, "7.10.0", true);
            // Update est config
            estConfiguration = (EstConfiguration) globalConfigSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            assertNull("After running post-upgrade vendor CAs with the old format should be gone",
                    estConfiguration.getValue(estAlias + "." + CmpConfiguration.CONFIG_VENDORCA, estAlias));
            // No vendor CAs
            estConfiguration.addAlias(estAliasNoVendors);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, estConfiguration);
            assertNull("No vendor CAs should be stored",
                    estConfiguration.getValue(estAliasNoVendors + "." + EstConfiguration.CONFIG_VENDORCA, estAliasNoVendors));
            assertEquals("Vendor CA IDs should be initialized but empty",
                    "",
                    estConfiguration.getValue(estAliasNoVendors + "." + EstConfiguration.CONFIG_VENDORCAIDS, estAliasNoVendors));
        } finally {
            estConfiguration.removeAlias(estAlias);
            estConfiguration.removeAlias(estAliasNoVendors);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, estConfiguration);
        }
    }

    @Test
    public void testUpgradeDocSigningEKU800() throws AuthorizationDeniedException {
        // Set previous upgraded to 7.11 (config is backed up and restored in After method)
        final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("7.11.0");
        guc.setPostUpgradedToVersion("7.11.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        // Make sure the EKU OID is removed so we can see that it shows up after upgrade
        AvailableExtendedKeyUsagesConfiguration config =
                (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
        if (config.isExtendedKeyUsageSupported("1.3.6.1.5.5.7.3.36")) {
            config.removeExtKeyUsage("1.3.6.1.5.5.7.3.36");
        }
        assertFalse("Doc signing EKU should not be present after removal", config.isExtendedKeyUsageSupported("1.3.6.1.5.5.7.3.36"));
        // Upgrade to 8.0.0, doc signing eku should now appear
        upgradeSession.upgrade(null, "7.11.0", false);
        config = (AvailableExtendedKeyUsagesConfiguration) globalConfigSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
        assertTrue("Doc signing EKU should be present after upgrade", config.isExtendedKeyUsageSupported("1.3.6.1.5.5.7.3.36"));
    }
    
    @Test
    public void testMigrateOcspSettings830() throws AuthorizationDeniedException {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        //Store old value
        long oldUntilNextUpdate = globalOcspConfiguration.getDefaultValidityTime();
        long oldMaxAge = globalOcspConfiguration.getDefaultResponseMaxAge();
        boolean oldUseMaxAgeForExpired = globalOcspConfiguration.getUseMaxValidityForExpiration();
        try {
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("8.0.0");
            guc.setPostUpgradedToVersion("8.0.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set ocsp.untilNextUpdate to a non-default value
            cesecoreConfigSession.setConfigurationValue("ocsp.untilNextUpdate", "50");
            cesecoreConfigSession.setConfigurationValue("ocsp.maxAge", "60");
            cesecoreConfigSession.setConfigurationValue("ocsp.expires.useMaxAge", "true");
            upgradeSession.upgrade(null, "8.0.0", false);
            globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertEquals("ocsp.untilNextUpdate was not migrated to GlobalOcspConfiguration", 50, globalOcspConfiguration.getDefaultValidityTime());
            assertEquals("ocsp.maxAge was not migrated to GlobalOcspConfiguration", 60, globalOcspConfiguration.getDefaultResponseMaxAge());
            assertEquals("ocsp.expires.useMaxAg was not migrated to GlobalOcspConfiguration", true, globalOcspConfiguration.getUseMaxValidityForExpiration());
        } finally {
            //Restore old values
            globalOcspConfiguration.setDefaultValidityTime(oldUntilNextUpdate);
            globalOcspConfiguration.setDefaultResponseMaxAge(oldMaxAge);
            globalOcspConfiguration.setUseMaxValidityForExpiration(oldUseMaxAgeForExpired);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }

    }
    
    @Test
    public void testRemoveConfigurationCheckerPost830() throws AuthorizationDeniedException {
        //First make sure that there is a Configuration Checker config
        if(globalConfigurationProxySession.findByConfigurationId(ConfigurationCheckerConfiguration.CONFIGURATION_ID) == null) {
            globalConfigurationProxySession.addConfiguration( new ConfigurationCheckerConfiguration());
        }
        
        if(globalConfigurationProxySession.findByConfigurationId(ConfigurationCheckerConfiguration.CONFIGURATION_ID) == null) {
            throw new IllegalStateException("No ConfigurationCheckerConfiguration present, test cannot continue.");
        }
        
        final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedToVersion("8.0.0");
        guc.setPostUpgradedToVersion("8.0.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        upgradeSession.upgrade(null, "8.0.0", true);
        
        assertNull("ConfigurationCheckerConfiguration was not removed.", globalConfigurationProxySession.findByConfigurationId(ConfigurationCheckerConfiguration.CONFIGURATION_ID));
        
    }
    
    @Test
    public void testMigrateCtCacheValues920() throws AuthorizationDeniedException {
       
        GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration) globalConfigSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        boolean oldEnableCache = globalCesecoreConfiguration.getCtCacheEnabled();
        long oldCacheSize = globalCesecoreConfiguration.getCtCacheSize();
        long oldCleanupInterval = globalCesecoreConfiguration.getCtCacheCleanupInterval();
        boolean oldFastFail = globalCesecoreConfiguration.getCtCacheFastFailEnabled();
        long oldBackoff = globalCesecoreConfiguration.getCtCacheFastFailBackoff();
        try {
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("8.3.0");
            guc.setPostUpgradedToVersion("8.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set some non-default values to test with
            cesecoreConfigSession.setConfigurationValue("ct.cache.enabled", "false");
            cesecoreConfigSession.setConfigurationValue("ct.cache.maxentries", "200");
            cesecoreConfigSession.setConfigurationValue("ct.cache.cleanupinterval", "300");
            cesecoreConfigSession.setConfigurationValue("ct.fastfail.enabled", "false");
            cesecoreConfigSession.setConfigurationValue("ct.fastfail.backoff", "400");
            //Perform upgrade
            upgradeSession.upgrade(null, "8.3.0", false);
            //Verify values
            globalCesecoreConfiguration = (GlobalCesecoreConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
            assertEquals("CT Cache Enable was not upgraded as expected", false, globalCesecoreConfiguration.getCtCacheEnabled());
            assertEquals("CT Cache Size was not upgraded as expected", 200, globalCesecoreConfiguration.getCtCacheSize());
            assertEquals("CT Cache Cleanup Interval was not upgraded as expected", 300, globalCesecoreConfiguration.getCtCacheCleanupInterval());
            assertEquals("CT Cache Fast Fail Enable was not upgraded as expected", false, globalCesecoreConfiguration.getCtCacheFastFailEnabled());
            assertEquals("CT Cache Fast Fail Backoff was not upgraded as expected", 400, globalCesecoreConfiguration.getCtCacheFastFailBackoff());         
        } finally {
            //Restore old values
            globalCesecoreConfiguration.setCtCacheEnabled(oldEnableCache);
            globalCesecoreConfiguration.setCtCacheSize(oldCacheSize);
            globalCesecoreConfiguration.setCtCacheCleanupInterval(oldCleanupInterval);
            globalCesecoreConfiguration.setCtCacheFastFailEnabled(oldFastFail);
            globalCesecoreConfiguration.setCtCacheFastFailBackoff(oldBackoff);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalCesecoreConfiguration);
        }
    }
    
    @Test
    public void testRemoveUserDataSourceAccessRulesPost930() throws AuthorizationDeniedException, RoleExistsException {
        final String rolename = "testRemoveUserDataSourceAccessRulesPost930";
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.2.0");
            guc.setPostUpgradedToVersion("9.2.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set up a role which uses the user data source rules
           
            
            LinkedHashMap<String, Boolean> rules = new LinkedHashMap<>();
            rules.put(AccessRulesConstants.REGULAR_EDITUSERDATASOURCES, Role.STATE_ALLOW);
            final String userDataSourceRule = AccessRulesConstants.USERDATASOURCEPREFIX + "123" + AccessRulesConstants.UDS_FETCH_RIGHTS;
            rules.put(userDataSourceRule, Role.STATE_ALLOW);
            Role role = new Role(null, rolename, rules);
            Role persistedRole = roleSession.persistRole(alwaysAllowtoken, role);
            //Verify that the rules exist
            LinkedHashMap<String, Boolean> persistedRules = persistedRole.getAccessRules();
            //Adding a slash here, since it seems to get added automatically. Upgradessessionbean uses startsWith anyway, so doesn't affect functionality. 
            if(!persistedRules.containsKey(AccessRulesConstants.REGULAR_EDITUSERDATASOURCES + "/")) {
                throw new IllegalStateException("User data source rules not persisted, test cannot continue.");
            }
            
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.2.0", /* post upgrade? */ true);
            
            Role upgradedRole = roleSession.getRole(alwaysAllowtoken, persistedRole.getRoleId());
            LinkedHashMap<String, Boolean> upgradedRules = upgradedRole.getAccessRules();
            assertFalse("User data source access rule was not automagically removed.", upgradedRules.containsKey(AccessRulesConstants.REGULAR_EDITUSERDATASOURCES + "/"));
            assertFalse("User data source access rule was not automagically removed.", upgradedRules.containsKey(userDataSourceRule));
            
            
        } finally {
            roleSession.deleteRoleIdempotent(alwaysAllowtoken, null, rolename);
            
            
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
        }
    }
    
    @Test
    public void testMigrateOcspOptions9_4_0() throws AuthorizationDeniedException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final boolean includeSignerCertCurrent = currentGlobalOcspConfiguration.getIncludeSigningCertificate();
        final boolean includeCertChainCurrent = currentGlobalOcspConfiguration.getIncludeCertificateChain();
        
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set the values to non-default. 
            cesecoreConfigSession.setConfigurationValue("ocsp.includesignercert", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.includecertchain", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.reqsigncertrevcachetime", "30000");
            
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Retrieve config and verify upgrade
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertFalse("ocsp.includesignercert was not migrated.", globalOcspConfiguration.getIncludeSigningCertificate());
            assertFalse("ocsp.includecertchain was not migrated.", globalOcspConfiguration.getIncludeCertificateChain());
            assertEquals("ocsp.reqsigncertrevcachetime was not migrated", 30000L, globalOcspConfiguration.getRequestSignserRevocationStatusCacheTime());
            
        } finally {
                       
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.4.0");
            guc.setPostUpgradedToVersion("9.4.0");
            
            //Set values to current
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setIncludeSigningCertificate(includeSignerCertCurrent);
            globalOcspConfiguration.setIncludeCertificateChain(includeCertChainCurrent);
            globalConfigurationProxySession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }
    }
    
    @Test
    public void testMigrateOcspSigningCertificateValidTime9_4_0() throws AuthorizationDeniedException, InvalidConfigurationException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        GlobalCaConfiguration currentGlobalCaConfiguration = (GlobalCaConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
        final long currentSigningCertificateValiditytime = currentGlobalOcspConfiguration.getSigningCertificateValidityTimeMilliseconds();
        final long currentCaCertificateCacheTime = currentGlobalCaConfiguration.getCaCertificateCacheTimeMillis();
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            
            cesecoreConfigSession.setConfigurationValue("ocsp.signingCertsValidTime", "5");
            
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Retrieve config and verify upgrade
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            GlobalCaConfiguration globalCaConfiguration = (GlobalCaConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
            //Original configuration is in seconds, new one is in ms
            assertEquals("ocsp.signingCertsValidTime was not migrated to database.", 5000, globalOcspConfiguration.getSigningCertificateValidityTimeMilliseconds());
            assertEquals("ocsp.signingCertsValidTime was not migrated to database.", 5000, globalCaConfiguration.getCaCertificateCacheTimeMillis());
        } finally {
            
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.4.0");
            guc.setPostUpgradedToVersion("9.4.0");            
            //Set values to current
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setSigningCertificateValidityTimeMilliseconds(currentSigningCertificateValiditytime);
            globalConfigurationProxySession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
            GlobalCaConfiguration globalCaConfiguration = (GlobalCaConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
            globalCaConfiguration.setCaCertificateCacheTimeMillis(currentCaCertificateCacheTime);
            globalConfigurationProxySession.saveConfiguration(alwaysAllowtoken, globalCaConfiguration);
        }
    }
    
    /**
     * 
     * Test that a negative value gets translated into 0
     */
    @Test
    public void testMigrateOcspSigningCertificateValidTimeNegative9_4_0() throws AuthorizationDeniedException, InvalidConfigurationException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        GlobalCaConfiguration currentGlobalCaConfiguration = (GlobalCaConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
        final long currentSigningCertificateValiditytime = currentGlobalOcspConfiguration.getSigningCertificateValidityTimeMilliseconds();
        final long currentCaCertificateCacheTime = currentGlobalCaConfiguration.getCaCertificateCacheTimeMillis();
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            
            cesecoreConfigSession.setConfigurationValue("ocsp.signingCertsValidTime", "-5");
            
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Retrieve config and verify upgrade
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            GlobalCaConfiguration globalCaConfiguration = (GlobalCaConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
            //Original configuration is in seconds, new one is in ms
            assertEquals("ocsp.signingCertsValidTime was not migrated to database.", 0, globalOcspConfiguration.getSigningCertificateValidityTimeMilliseconds());
            assertEquals("ocsp.signingCertsValidTime was not migrated to database.", 0, globalCaConfiguration.getCaCertificateCacheTimeMillis());
        } finally {
            
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.4.0");
            guc.setPostUpgradedToVersion("9.4.0");            
            //Set values to current
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setSigningCertificateValidityTimeMilliseconds(currentSigningCertificateValiditytime);
            globalConfigurationProxySession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
            GlobalCaConfiguration globalCaConfiguration = (GlobalCaConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
            globalCaConfiguration.setCaCertificateCacheTimeMillis(currentCaCertificateCacheTime);
            globalConfigurationProxySession.saveConfiguration(alwaysAllowtoken, globalCaConfiguration);

        }
    }

    @Test
    public void testOcspCleanupSchedule940() throws AuthorizationDeniedException {
        final GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        final boolean originalOcspCleanUp = currentGlobalOcspConfiguration.getOcspCleanupUse();
        final String originalOcspCleanUpSchedule = currentGlobalOcspConfiguration.getOcspCleanupSchedule();
        final String originalOcspCleanUpUnit = currentGlobalOcspConfiguration.getOcspCleanupScheduleUnit();

        try {
            // Set up deprecated values in GlobalConfiguration
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            globalConfiguration.setOcspCleanupUse(true);
            globalConfiguration.setOcspCleanupSchedule("66");
            globalConfiguration.setOcspCleanupScheduleUnit("MINUTES");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalConfiguration);

            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);

            // Perform upgrade, without post upgrade
            upgradeSession.upgrade(null, "9.3.0", false);

            // Verify migration
            final GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertTrue("ocsp.cleanup.use was not migrated.", globalOcspConfiguration.getOcspCleanupUse());
            assertEquals("ocsp.cleanup.schedule was not migrated", "66", globalOcspConfiguration.getOcspCleanupSchedule());
            assertEquals("ocsp.cleanup.schedule_unit was not migrated", "MINUTES", globalOcspConfiguration.getOcspCleanupScheduleUnit());

            // Perform post-upgrade and verify old values are cleared from database.
            upgradeSession.upgrade(null, "9.3.0", true);
            globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            LinkedHashMap<Object, Object> data = globalConfiguration.getRawData();
            assertFalse("ocsp.cleanup.use was not cleared from database.", data.containsKey("ocsp.cleanup.use"));
            assertFalse("ocsp.cleanup.schedule was not cleared from database.", data.containsKey("ocsp.cleanup.schedule"));
            assertFalse("ocsp.cleanup.schedule_unit was not cleared from database.", data.containsKey("ocsp.cleanup.schedule_unit"));
        } finally {
            //Set values to back to current
            final GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setOcspCleanupUse(originalOcspCleanUp);
            globalOcspConfiguration.setOcspCleanupSchedule(originalOcspCleanUpSchedule);
            globalOcspConfiguration.setOcspCleanupScheduleUnit(originalOcspCleanUpUnit);
            globalConfigurationProxySession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }
    }

    @Test
    public void testEEPLimitationsMigration940() throws AuthorizationDeniedException {
        GlobalEndEntityProfileConfiguration globalEEPConfiguration = (GlobalEndEntityProfileConfiguration) globalConfigSession.getCachedConfiguration(GlobalEndEntityProfileConfiguration.EEP_CONFIGURATION_ID);
        final boolean originalEEPLimitations = globalEEPConfiguration.getEnableEndEntityProfileLimitations();

        try {
            // Have GC a different value for EEP Limitations
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            globalConfiguration.setEnableEndEntityProfileLimitations(!originalEEPLimitations);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalConfiguration);

            final GlobalUpgradeConfiguration globalUpgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            globalUpgradeConfiguration.setUpgradedToVersion("9.3.0");
            globalUpgradeConfiguration.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalUpgradeConfiguration);

            // Perform upgrade
            upgradeSession.upgrade(null, "9.3.0", false);
            globalEEPConfiguration = (GlobalEndEntityProfileConfiguration) globalConfigSession.getCachedConfiguration(GlobalEndEntityProfileConfiguration.EEP_CONFIGURATION_ID);
            assertEquals("endentityprofilelimitations value was not migrated.", !originalEEPLimitations, globalEEPConfiguration.getEnableEndEntityProfileLimitations());

            // Perform post-upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ true);
            globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            LinkedHashMap<Object, Object> data = globalConfiguration.getRawData();
            assertFalse("endentityprofilelimitations was not removed from GlobalConfigData in post-upgrade.", data.containsKey("endentityprofilelimitations"));

        } finally {
            //Restore the original value
            globalEEPConfiguration.setEnableEndEntityProfileLimitations(originalEEPLimitations);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalEEPConfiguration);

        }
    }
    
    @Test
    public void testMigrateOcspNonExistingValuesGlobal_9_4_0_Good() throws AuthorizationDeniedException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        OcspNonExistingBehavior originalValue = currentGlobalOcspConfiguration.getOcspNonExistingBehavior();
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set the values to something non-default
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisgood", "true");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisrevoked", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisunauthorized", "false");
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Check the value
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertEquals("ocsp.nonexistingisgood=true was not upgraded.", OcspNonExistingBehavior.GOOD, globalOcspConfiguration.getOcspNonExistingBehavior());
        } finally {
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setOcspNonExistingBehavior(originalValue);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }    
    }
    
    @Test
    public void testMigrateOcspNonExistingValuesGlobal_9_4_0_Unknown() throws AuthorizationDeniedException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        OcspNonExistingBehavior originalValue = currentGlobalOcspConfiguration.getOcspNonExistingBehavior();
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set the values to something non-default
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisgood", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisrevoked", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisunauthorized", "false");
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Check the value
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertEquals("ocsp.nonexistingis unkown status was not upgraded.", OcspNonExistingBehavior.UNKNOWN, globalOcspConfiguration.getOcspNonExistingBehavior());
        } finally {
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setOcspNonExistingBehavior(originalValue);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }   
    }
    
    @Test
    public void testMigrateOcspNonExistingValuesGlobal_9_4_0_Revoked() throws AuthorizationDeniedException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        OcspNonExistingBehavior originalValue = currentGlobalOcspConfiguration.getOcspNonExistingBehavior();
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set the values to something non-default
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisgood", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisrevoked", "true");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisunauthorized", "false");
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Check the value
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertEquals("ocsp.nonexistingisrevoked=true was not upgraded.", OcspNonExistingBehavior.REVOKED, globalOcspConfiguration.getOcspNonExistingBehavior());
        } finally {
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setOcspNonExistingBehavior(originalValue);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }    
    }
    
    @Test
    public void testMigrateOcspNonExistingValuesGlobal_9_4_0_Unauthorized() throws AuthorizationDeniedException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        OcspNonExistingBehavior originalValue = currentGlobalOcspConfiguration.getOcspNonExistingBehavior();
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set the values to something non-default
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisgood", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisrevoked", "false");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisunauthorized", "true");
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Check the value
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            assertEquals("ocsp.nonexistingisunauthorized=true was not upgraded.", OcspNonExistingBehavior.UNAUTHORIZED, globalOcspConfiguration.getOcspNonExistingBehavior());
        } finally {
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setOcspNonExistingBehavior(originalValue);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
        }    
    }
    
    @Test
    public void testMigrateOcspNonExistingValuesGlobal_9_4_0_failOnMultiple() throws AuthorizationDeniedException {
        GlobalOcspConfiguration currentGlobalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        OcspNonExistingBehavior originalValue = currentGlobalOcspConfiguration.getOcspNonExistingBehavior();
        String nonexistingisgood = cesecoreConfigSession.getConfigurationValue("ocsp.nonexistingisgood");
        String nonexistingisrevoked = cesecoreConfigSession.getConfigurationValue("ocsp.nonexistingisrevoked");
        String nonexistingisunauthorized = cesecoreConfigSession.getConfigurationValue("ocsp.nonexistingisunauthorized");
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Set the values to something non-default
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisgood", "true");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisrevoked", "true");
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisunauthorized", "false");
            //Perform upgrade
            boolean result = upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            assertFalse("Upgrade should have failed if multiple values were set to true", result);
        } finally {
            GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationProxySession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            globalOcspConfiguration.setOcspNonExistingBehavior(originalValue);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalOcspConfiguration);
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisgood", nonexistingisgood);
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisrevoked", nonexistingisrevoked);
            cesecoreConfigSession.setConfigurationValue("ocsp.nonexistingisunauthorized", nonexistingisunauthorized);
        }    
    }
     
    @Test
    public void testUpgradeOcspResponders9_4_0() throws InternalKeyBindingNameInUseException, AuthorizationDeniedException, CryptoTokenOfflineException, InvalidAlgorithmException, InternalKeyBindingNonceConflictException {
        final String responderName = "testUpgradeOcspResponders9_4_0";
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(alwaysAllowtoken, "foo123".toCharArray(), true, false, responderName,
                "1024", "1024", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);     
        
        final Map<String, Serializable> dataMap = new LinkedHashMap<>();
        dataMap.put("nonexistingisgood", Boolean.TRUE);
        int keyBindingId = internalKeyBindingSession.createInternalKeyBinding(alwaysAllowtoken, OcspKeyBinding.IMPLEMENTATION_ALIAS, responderName, InternalKeyBindingStatus.ACTIVE, null,
                cryptoTokenId, CAToken.SOFTPRIVATESIGNKEYALIAS,  AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap, null);
        
        OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingSession.getInternalKeyBinding(alwaysAllowtoken, keyBindingId);
        assertEquals(true, ocspKeyBinding.getNonExistingGood());
        try {
            //Set up EJBCA in a pre-upgrade state
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Retrieve responder, verify that upgrade was performed
            OcspKeyBinding upgradedResponder = (OcspKeyBinding) internalKeyBindingSession.getInternalKeyBinding(alwaysAllowtoken, keyBindingId);
            assertEquals("OCSP Responder was not upgraded to 9.4.0 standard", OcspNonExistingBehavior.GOOD, upgradedResponder.getOcspNonExistingBehavior());
            
        } finally {
            internalKeyBindingSession.deleteInternalKeyBinding(alwaysAllowtoken, keyBindingId);
            CryptoTokenTestUtils.removeCryptoToken(alwaysAllowtoken, cryptoTokenId);
        }
    }
    
    @Test
    public void testMigrateCaConfiguration9_4_0() throws AuthorizationDeniedException {
        //Stash the original value
        GlobalCaConfiguration globalCaConfiguration = (GlobalCaConfiguration) globalConfigSession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
        boolean originalValue = globalCaConfiguration.getEnableIcaoCANameChange();
        
        try {
            //Make sure there is a (non-default) value to upgrade from 
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            globalConfiguration.setEnableIcaoCANameChange(true);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalConfiguration);
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            
            //Verify that the non-default value has been migrated
            globalCaConfiguration = (GlobalCaConfiguration) globalConfigSession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
            assertTrue("enableIcaoNameChange value was not migrated.", globalCaConfiguration.getEnableIcaoCANameChange());
            
            //Perform post-upgrade and verify that the value is removed from globalconfigdata
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ true);
            globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            LinkedHashMap<Object, Object> data = globalConfiguration.getRawData();
            assertFalse("enableicaocanamechange was not removed from GlobalConfigData in post-upgrade.", data.containsKey("enableicaocanamechange"));
            
            
        } finally {
            //Restore the original value
            globalCaConfiguration.setEnableIcaoCANameChange(originalValue);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalCaConfiguration);
            
        }
    }
    
    @Test
    public void testMigrateCtConfiguration9_4_0() throws AuthorizationDeniedException {
        //Stash the original values
        final GlobalCtConfiguration originalGlobalCtConfiguration = (GlobalCtConfiguration) globalConfigSession.getCachedConfiguration(GlobalCtConfiguration.CT_CONFIGURATION_ID);
        try {
            //Set some non-default values 
            GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration) globalConfigSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
            globalCesecoreConfiguration.setCtCacheEnabled(false);
            globalCesecoreConfiguration.setCtCacheCleanupInterval(1);
            globalCesecoreConfiguration.setCtCacheSize(2);
            globalCesecoreConfiguration.setCtCacheFastFailEnabled(false);
            globalCesecoreConfiguration.setCtCacheFastFailBackoff(3);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalCesecoreConfiguration);
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            GoogleCtPolicy googleCtPolicy = new GoogleCtPolicy();
            List<PolicyBreakpoint> breakpoints = new ArrayList<>();
            breakpoints.add(new PolicyBreakpoint(0, 12, 11));
            googleCtPolicy.setBreakpoints(breakpoints);
            globalConfiguration.setGoogleCtPolicy(googleCtPolicy);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, globalConfiguration);
            //Set the upgrade-from version 
            final GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession
                    .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
            guc.setUpgradedToVersion("9.3.0");
            guc.setPostUpgradedToVersion("9.3.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            //Perform upgrade
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ false);
            //Verify upgrade
            GlobalCtConfiguration globalCtConfiguration = (GlobalCtConfiguration) globalConfigSession.getCachedConfiguration(GlobalCtConfiguration.CT_CONFIGURATION_ID);
            assertEquals("Google CT policy was not migrated from GlobalConfiguration", googleCtPolicy, globalCtConfiguration.getGoogleCtPolicy());
            assertEquals("Value was not migrated from GlobalCesecoreConfiguration", false, globalCtConfiguration.getCtCacheEnabled());
            assertEquals("Value was not migrated from GlobalCesecoreConfiguration", 1, globalCtConfiguration.getCtCacheCleanupInterval());
            assertEquals("Value was not migrated from GlobalCesecoreConfiguration", 2, globalCtConfiguration.getCtCacheSize());
            assertEquals("Value was not migrated from GlobalCesecoreConfiguration", false, globalCtConfiguration.getCtCacheFastFailEnabled());
            assertEquals("Value was not migrated from GlobalCesecoreConfiguration", 3, globalCtConfiguration.getCtCacheFastFailBackoff());
            //Perform post-upgrade and verify that the values are removed from globalconfigdata 
            upgradeSession.upgrade(/* database */ null, /* upgrade from */ "9.3.0", /* post upgrade? */ true);
            globalConfiguration = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            LinkedHashMap<Object, Object> globalConfigData = globalConfiguration.getRawData();
            assertFalse("google_ct_policy was not removed from GlobalConfiguration in post-upgrade.", globalConfigData.containsKey("google_ct_policy"));
            globalCesecoreConfiguration = (GlobalCesecoreConfiguration) globalConfigSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
            LinkedHashMap<Object, Object> globalCesecoreConfigData = globalCesecoreConfiguration.getRawData();
            assertFalse("ct_cache_enabled was not removed from GlobalConfiguration in post-upgrade.", globalCesecoreConfigData.containsKey("ct_cache_enabled"));
            assertFalse("ct_cache_size was not removed from GlobalConfiguration in post-upgrade.", globalCesecoreConfigData.containsKey("ct_cache_size"));
            assertFalse("ct_cache_cleanup_interval was not removed from GlobalConfiguration in post-upgrade.", globalCesecoreConfigData.containsKey("ct_cache_cleanup_interval"));
            assertFalse("ct_cache_fast_fail_enabled was not removed from GlobalConfiguration in post-upgrade.", globalCesecoreConfigData.containsKey("ct_cache_fast_fail_enabled"));
            assertFalse("ct_cache_fast_fail_backoff was not removed from GlobalConfiguration in post-upgrade.", globalCesecoreConfigData.containsKey("ct_cache_fast_fail_backoff"));
            
        } finally {
            //Restore original value
            globalConfigSession.saveConfiguration(alwaysAllowtoken, originalGlobalCtConfiguration);
        }
    }

    private EndEntityInformation makeEndEntityInfo(final String username, final String startTime, final String endTime) {
        final ExtendedInformation extInfo = new ExtendedInformation();
        if (startTime != null) {
            extInfo.setCertificateStartTime(startTime);
            extInfo.setCertificateEndTime(endTime);
        }
        final EndEntityInformation endEntityInfo = new EndEntityInformation(username, "CN=" + username, testCaInfo.getCAId(), null, null, EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_USERGEN, extInfo);
        endEntityInfo.setPassword("foo123");
        return endEntityInfo;
    }
    
    private void deleteEndEntity(final String username) {
        try {
            endEntityManagementSession.deleteUser(alwaysAllowtoken, username);
        } catch (NoSuchEndEntityException e) {
            // Did not exist
        } catch (AuthorizationDeniedException | CouldNotRemoveEndEntityException e) {
            throw new IllegalStateException(e);
        }
    }

}
