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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataProxySessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileExistsException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension;
import org.ejbca.core.protocol.ocsp.extension.unid.OCSPUnidExtension;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * System tests for the upgrade session bean. 
 * 
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public class UpgradeSessionBeanTest {

    private static final Logger log = Logger.getLogger(UpgradeSessionBeanTest.class);
    private static final String TESTCLASS = UpgradeSessionBeanTest.class.getSimpleName();
    
    private ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private PublisherSessionRemote publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberDataProxySessionRemote roleMemberProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberDataProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private UpgradeSessionRemote upgradeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeSessionRemote.class);
    private UpgradeTestSessionRemote upgradeTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UpgradeTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalKeyBindingMgmtSessionRemote internalKeyBindingSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);


    private AuthenticationToken alwaysAllowtoken = new TestAlwaysAllowLocalAuthenticationToken("UpgradeSessionBeanTest");
    
    private AvailableCustomCertificateExtensionsConfiguration cceConfigBackup;
    private GlobalUpgradeConfiguration gucBackup;
    private GlobalConfiguration gcBackup;
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Before
    public void setUp() {
        cceConfigBackup = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        gucBackup = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        gcBackup = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }
    
    @After
    public void tearDown() throws Exception {
        globalConfigSession.saveConfiguration(alwaysAllowtoken, cceConfigBackup);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, gucBackup);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, gcBackup);
    }
    
    /**
     * This test will perform the upgrade step to 6.4.0, which is update of access rules, adding read-only rules to any roles which previously had them.
     * 
     */
    @Test
    public void testUpgradeTo640AuditorRole() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        //Create a role specifically to test that read only access is given. 
        final String readOnlyRoleName = TESTCLASS + " ReadOnlyRole"; 
        final List<AccessRuleData> oldAccessRules = Arrays.asList(
                new AccessRuleData(readOnlyRoleName, AccessRulesConstants.REGULAR_ACTIVATECA, AccessRuleState.RULE_ACCEPT, false),
                new AccessRuleData(readOnlyRoleName, StandardRules.CAFUNCTIONALITY.resource(), AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(readOnlyRoleName, StandardRules.CERTIFICATEPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, false),
                new AccessRuleData(readOnlyRoleName, AccessRulesConstants.REGULAR_EDITPUBLISHER, AccessRuleState.RULE_ACCEPT, false),
                new AccessRuleData(readOnlyRoleName, AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false),
                new AccessRuleData(readOnlyRoleName, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, false),
                new AccessRuleData(readOnlyRoleName, InternalKeyBindingRules.BASE.resource(), AccessRuleState.RULE_ACCEPT, false)
                );
        final List<AccessUserAspectData> oldAccessUserAspectDatas = Arrays.asList(
                new AccessUserAspectData(readOnlyRoleName, 1, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, "CN=foo")
                );
        upgradeTestSession.createRole(readOnlyRoleName, oldAccessRules, oldAccessUserAspectDatas);
        try {
            upgradeSession.upgrade(null, "6.3.2", false);
            final List<AccessRuleData> upgradedAccessRules = upgradeTestSession.getAccessRuleDatas(readOnlyRoleName);
            // Access implied by /ca_functionality +recursive granted to the role
            assertAccessRuleDataIsNotPresent(upgradedAccessRules, readOnlyRoleName, StandardRules.CAVIEW.resource(), false);
            assertAccessRuleDataIsNotPresent(upgradedAccessRules, readOnlyRoleName, StandardRules.CERTIFICATEPROFILEVIEW.resource(), false);
            assertAccessRuleDataIsNotPresent(upgradedAccessRules, readOnlyRoleName, AccessRulesConstants.REGULAR_VIEWPUBLISHER, false);
            // Additional access that should have been granted to this role
            assertAccessRuleDataIsPresent(upgradedAccessRules, readOnlyRoleName, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, false);
            assertAccessRuleDataIsPresent(upgradedAccessRules, readOnlyRoleName, AccessRulesConstants.SERVICES_EDIT, false);
            assertAccessRuleDataIsPresent(upgradedAccessRules, readOnlyRoleName, AccessRulesConstants.SERVICES_VIEW, false);
            assertAccessRuleDataIsPresent(upgradedAccessRules, readOnlyRoleName, AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW, true);
            assertAccessRuleDataIsPresent(upgradedAccessRules, readOnlyRoleName, InternalKeyBindingRules.VIEW.resource(), true);
        } finally {
            upgradeTestSession.deleteRole(readOnlyRoleName);
            deleteRole(null, readOnlyRoleName);
        }
    }
    
   /**
    * This test will perform the upgrade step to 6.4.0 and tests update of access rules. Rules specific to editing available extended key usages and 
    * custom certificate extensions should be added to any role that is already allowed to edit system configurations, but not other roles.
    */
   @Test
   public void testUpgradeTo640EKUAndCustomCertExtensionsAccessRules() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
       // Add a role whose access rules should change after upgrade
       final String sysConfigRoleName = TESTCLASS + " SystemConfigRole"; 
       final List<AccessRuleData> oldSysConfigAccessRules = Arrays.asList(
               new AccessRuleData(sysConfigRoleName, StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false)
               );
       upgradeTestSession.createRole(sysConfigRoleName, oldSysConfigAccessRules, null);
       // Add a role whose access rules should NOT change after upgrade (except for also being allowed to view EEPs)
       final String caAdmRoleName = TESTCLASS + " CaAdminRole"; 
       final List<AccessRuleData> oldCaAdmAccessRules = Arrays.asList(
               new AccessRuleData(caAdmRoleName, StandardRules.CAFUNCTIONALITY.resource(), AccessRuleState.RULE_ACCEPT, true),
               new AccessRuleData(caAdmRoleName, StandardRules.CERTIFICATEPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, false),
               new AccessRuleData(caAdmRoleName, AccessRulesConstants.REGULAR_EDITPUBLISHER, AccessRuleState.RULE_ACCEPT, false),
               new AccessRuleData(caAdmRoleName, AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false)
               );
       upgradeTestSession.createRole(caAdmRoleName, oldCaAdmAccessRules, null);
       try {
           upgradeSession.upgrade(null, "6.3.2", false);
           // Verify that sysConfigRole's access rules contained rules to edit available extended key usages and custom certificate extensions
           final List<AccessRuleData> upgradedSysConfigAccessRules = upgradeTestSession.getAccessRuleDatas(sysConfigRoleName);
           assertEquals(6, upgradedSysConfigAccessRules.size());
           assertAccessRuleDataIsPresent(upgradedSysConfigAccessRules, sysConfigRoleName, StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), false);
           assertAccessRuleDataIsPresent(upgradedSysConfigAccessRules, sysConfigRoleName, StandardRules.EKUCONFIGURATION_EDIT.resource(), false);
           assertAccessRuleDataIsPresent(upgradedSysConfigAccessRules, sysConfigRoleName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(), false);

           // Verify that caAdmRole's access rules do not contain new unexpected rules
           final List<AccessRuleData> upgradedCaAdmAccessRules = upgradeTestSession.getAccessRuleDatas(caAdmRoleName);
           assertEquals("Unexpected number of access rules: " + Arrays.toString(upgradedCaAdmAccessRules.toArray()), oldCaAdmAccessRules.size()+1, upgradedCaAdmAccessRules.size());
           // The old rules should still be present
           for (final AccessRuleData accessRuleData : oldCaAdmAccessRules) {
               assertAccessRuleDataIsPresent(upgradedCaAdmAccessRules, caAdmRoleName, accessRuleData.getAccessRuleName(), accessRuleData.getRecursive());
           }
           // Since edit of EEPs was granted, so should viewing now
           assertAccessRuleDataIsPresent(upgradedCaAdmAccessRules, caAdmRoleName, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, false);
           // As documentation of this tests purpose, perform some additional tests can never fail if the above has not failed
           // Since /ca_functionality was granted, /ca_functionality/view_certificate_profiles and /ca_functionality/view_publisher should not appear
           assertAccessRuleDataIsNotPresent(upgradedCaAdmAccessRules, caAdmRoleName, StandardRules.CERTIFICATEPROFILEVIEW.resource(), false);
           assertAccessRuleDataIsNotPresent(upgradedCaAdmAccessRules, caAdmRoleName, AccessRulesConstants.REGULAR_VIEWPUBLISHER, false);
           // Also check that unrelated access was not added
           assertAccessRuleDataIsNotPresent(upgradedCaAdmAccessRules, caAdmRoleName, StandardRules.EKUCONFIGURATION_EDIT.resource(), false);
           assertAccessRuleDataIsNotPresent(upgradedCaAdmAccessRules, caAdmRoleName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(), false);
       } finally {
           upgradeTestSession.deleteRole(sysConfigRoleName);
           upgradeTestSession.deleteRole(caAdmRoleName);
           deleteRole(null, sysConfigRoleName);
           deleteRole(null, caAdmRoleName);
       }
   }
   
   /**
    * This test checks that an upgrade to 6.6.0 adds view/edit access to approval profiles if you have view/edit access to certificate profiles. 
    */
   @Test
   public void testUpgradeTo660ApprovalRules() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
       final String testRoleName = TESTCLASS + " TestRole"; 
       // Test view (auditor) access
       try {
           final List<AccessRuleData> oldAccessRules = Arrays.asList(
                   new AccessRuleData(testRoleName, StandardRules.CERTIFICATEPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false)
                   );
           final List<AccessUserAspectData> oldAccessUserAspectDatas = Arrays.asList(
                   new AccessUserAspectData(testRoleName, 1, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, "CN=foo")
                   );
           upgradeTestSession.createRole(testRoleName, oldAccessRules, oldAccessUserAspectDatas);
           upgradeSession.upgrade(null, "6.5.1", false);
           final List<AccessRuleData> upgradedAccessRules = upgradeTestSession.getAccessRuleDatas(testRoleName);
           assertAccessRuleDataIsPresent(upgradedAccessRules, testRoleName, StandardRules.APPROVALPROFILEVIEW.resource(), false);
       } finally {
           upgradeTestSession.deleteRole(testRoleName);
           deleteRole(null, testRoleName);
       }
       // Test edit access
       try {
           final List<AccessRuleData> oldAccessRules = Arrays.asList(
                   new AccessRuleData(testRoleName, StandardRules.CERTIFICATEPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, false)
                   );
           final List<AccessUserAspectData> oldAccessUserAspectDatas = Arrays.asList(
                   new AccessUserAspectData(testRoleName, 1, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASEINS, "CN=foo")
                   );
           upgradeTestSession.createRole(testRoleName, oldAccessRules, oldAccessUserAspectDatas);
           upgradeSession.upgrade(null, "6.5.1", false);
           final List<AccessRuleData> upgradedAccessRules = upgradeTestSession.getAccessRuleDatas(testRoleName);
           assertAccessRuleDataIsPresent(upgradedAccessRules, testRoleName, StandardRules.APPROVALPROFILEEDIT.resource(), false);
       } finally {
           upgradeTestSession.deleteRole(testRoleName);
           deleteRole(null, testRoleName);
       }
   }
   
    /**
    * This test verifies that CAs and Certificate Profiles using approvals are automatically assigned approval profiles at upgrade. 
    */
   @Test
   public void testUpgradeTo660Approvals() throws CAExistsException, AuthorizationDeniedException, CertificateProfileExistsException, CADoesntExistsException, CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException, IOException {       
       //This CA should not be assigned an approval profile on account of lacking approvals
       List<Integer> approvalRequirements = new ArrayList<>();
       approvalRequirements.add(ApprovalRequestType.ACTIVATECA.getIntegerValue());
      
       //This CA should not be assigned an approval profile on account of lacking any actions
       X509CA noActionsCa =  CaTestUtils.createTestX509CA("CN=NoActions", "foo123".toCharArray(), false);
       noActionsCa.setNumOfRequiredApprovals(2);
       noActionsCa.setApprovalProfile(-1);
       caSession.addCA(alwaysAllowtoken, noActionsCa);
       
       //This CA should be assigned a profile on with two approvals 
       X509CA twoApprovalsCa =  CaTestUtils.createTestX509CA("CN=TwoApprovals", "foo123".toCharArray(), false);
       twoApprovalsCa.setNumOfRequiredApprovals(2);
       twoApprovalsCa.setApprovalSettings(approvalRequirements);
       caSession.addCA(alwaysAllowtoken, twoApprovalsCa);
       
       //This CA should be assigned a profile on with three approvals 
       X509CA threeApprovalsCa = CaTestUtils.createTestX509CA("CN=ThreeApprovals", "foo123".toCharArray(), false);
       threeApprovalsCa.setNumOfRequiredApprovals(3);
       threeApprovalsCa.setApprovalSettings(approvalRequirements);
       caSession.addCA(alwaysAllowtoken, threeApprovalsCa);
       
       //This certificate profile has approvals set, but nothing to approve. 
       String noActionsCertificateProfileName = "NoActionsCertificateProfile";
       CertificateProfile noActionsCertificateProfile = new CertificateProfile();
       noActionsCertificateProfile.setNumOfReqApprovals(2);
       certificateProfileSession.addCertificateProfile(alwaysAllowtoken, noActionsCertificateProfileName, noActionsCertificateProfile);    
              
       //This certificate profile should require two approvals, and should reuse the one from the CA
       CertificateProfile twoProfilesCertificateProfile = new CertificateProfile();
       twoProfilesCertificateProfile.setNumOfReqApprovals(2);
       twoProfilesCertificateProfile.setApprovalSettings(Arrays.asList(ApprovalRequestType.ADDEDITENDENTITY.getIntegerValue()));
       String certificateProfileName = "TwoApprovalsCertificateProfile";
       certificateProfileSession.addCertificateProfile(alwaysAllowtoken, certificateProfileName, twoProfilesCertificateProfile);      
     
       int twoApprovalProfileId = -1;
       int threeApprovalProfileId = -1;
       int noActionProfileId = -1;
       int noActionCertificateProfileId = -1;
       
       try {
           upgradeSession.upgrade(null, "6.5.1", false);
           
           CAInfo retrievedNoActionsCa = caSession.getCAInfo(alwaysAllowtoken, noActionsCa.getCAId());
           noActionProfileId = retrievedNoActionsCa.getApprovalProfile();
           assertEquals("Approval profile was created for CA with no approvals set.", -1, noActionProfileId);
           
           CAInfo retrievedTwoApprovalsCa = caSession.getCAInfo(alwaysAllowtoken, twoApprovalsCa.getCAId());
           twoApprovalProfileId = retrievedTwoApprovalsCa.getApprovalProfile();
           assertNotEquals("No approval profile was set for two approvals CA", -1, twoApprovalProfileId);
           AccumulativeApprovalProfile twoApprovalProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(twoApprovalProfileId);
           assertEquals("Correct number of approvals was not set in profile during upgrade.", 2, twoApprovalProfile.getNumberOfApprovalsRequired());
           
           CAInfo retrievedThreeApprovalsCa = caSession.getCAInfo(alwaysAllowtoken, threeApprovalsCa.getCAId());
           threeApprovalProfileId = retrievedThreeApprovalsCa.getApprovalProfile();
           AccumulativeApprovalProfile threeApprovalProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(threeApprovalProfileId);
           assertEquals("Correct number of approvals was not set in profile during upgrade.", 3, threeApprovalProfile.getNumberOfApprovalsRequired());
           
           CertificateProfile retrievedCertificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileName);
           assertEquals("Two approvals profile was not reused for certificate profile.", twoApprovalProfileId,
                    retrievedCertificateProfile.getApprovalProfileID());
            
            CertificateProfile retrievedNoActionCertificateProfile = certificateProfileSession.getCertificateProfile(noActionsCertificateProfileName);
            noActionCertificateProfileId = retrievedNoActionCertificateProfile.getApprovalProfileID();
            assertEquals("Approval profile was set for certificate profile lacking actions.", -1, noActionCertificateProfileId
                    );
            
        } finally {          
            if (twoApprovalProfileId != -1) {
                approvalProfileSession.removeApprovalProfile(alwaysAllowtoken, twoApprovalProfileId);
            }
            if (threeApprovalProfileId != -1) {
                approvalProfileSession.removeApprovalProfile(alwaysAllowtoken, threeApprovalProfileId);
            }
            if (noActionProfileId != -1) {
                approvalProfileSession.removeApprovalProfile(alwaysAllowtoken, noActionProfileId);
            }
            if (noActionCertificateProfileId != -1) {
                approvalProfileSession.removeApprovalProfile(alwaysAllowtoken, noActionCertificateProfileId);
            }
            CaTestUtils.removeCa(alwaysAllowtoken, noActionsCa.getCAInfo());
            CaTestUtils.removeCa(alwaysAllowtoken, twoApprovalsCa.getCAInfo());
            CaTestUtils.removeCa(alwaysAllowtoken, threeApprovalsCa.getCAInfo());
            certificateProfileSession.removeCertificateProfile(alwaysAllowtoken, certificateProfileName);
            certificateProfileSession.removeCertificateProfile(alwaysAllowtoken, noActionsCertificateProfileName);
            
       }
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
    
    /**
     * This test checks the automatic upgrade to 6.4.2, namely that:
     * 
     * 1. Auditors are given the new default rights introduced in 6.4.2
     * 2. That roles that had edit access to pages that have been given read rights now also have read rights. 
     * @throws AuthorizationDeniedException 
     * @throws RoleExistsException 
     * @throws RoleNotFoundException 
     */
    @Test
    public void testUpgradeTo642AuditorRole() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        final String oldAuditorName = TESTCLASS + " 640Auditor"; 
        final String editSystemAdminName = TESTCLASS + " EditSystemAdmin";
        try {
            final Set<String> newRules = new HashSet<>(Arrays.asList(
                    StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
                    StandardRules.EKUCONFIGURATION_VIEW.resource(),
                    StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(),
                    StandardRules.VIEWROLES.resource(),
                    AccessRulesConstants.REGULAR_VIEWENDENTITY
                    ));
            // Create an auditor according to 6.4.0, i.e. ignoring the new rules.
            final List<AccessRuleData> oldAuditorRules = new ArrayList<>();
            final List<AccessRuleData> accessRuleTemplates = Arrays.asList(
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false), 
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, AuditLogRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true), 
                    new AccessRuleData(oldAuditorName, InternalKeyBindingRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true),
                    new AccessRuleData(oldAuditorName, StandardRules.CAVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, StandardRules.CERTIFICATEPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, StandardRules.APPROVALPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, CryptoTokenRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true),
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.REGULAR_VIEWPUBLISHER, AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.SERVICES_VIEW, AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW, AccessRuleState.RULE_ACCEPT, true),
                    new AccessRuleData(oldAuditorName, StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, StandardRules.EKUCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, StandardRules.VIEWROLES.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(oldAuditorName, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false)
                    );
            for (final AccessRuleData accessRuleTemplate : accessRuleTemplates) {
                if (!newRules.contains(accessRuleTemplate.getAccessRuleName())) {
                    oldAuditorRules.add(accessRuleTemplate);
                }
            }
            upgradeTestSession.createRole(oldAuditorName, oldAuditorRules, null);
            // Confirm that auditor doesn't have access to rules prematurely
            final List<AccessRuleData> preUpgradeAccessRuleData = upgradeTestSession.getAccessRuleDatas(oldAuditorName);
            for (String newRule : newRules) {
                assertAccessRuleDataIsNotPresent(preUpgradeAccessRuleData, oldAuditorName, newRule, false);
            }
            // Create an auditor with access to the old edit rules. 
            final List<AccessRuleData> oldEditAdminRules = Arrays.asList(
                    new AccessRuleData(editSystemAdminName, StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(editSystemAdminName, StandardRules.EKUCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(editSystemAdminName, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false),
                    new AccessRuleData(editSystemAdminName, StandardRules.EDITROLES.resource(), AccessRuleState.RULE_ACCEPT, false)
                    );
            upgradeTestSession.createRole(editSystemAdminName, oldEditAdminRules, null);
            // Perform upgrade. 
            upgradeSession.upgrade(null, "6.4.0", false);
            final List<AccessRuleData> upgradedAuditorAccessRuleData = upgradeTestSession.getAccessRuleDatas(oldAuditorName);
            for (String newRule : newRules) {
                assertAccessRuleDataIsPresent(upgradedAuditorAccessRuleData, oldAuditorName, newRule, false);
            }
            final List<AccessRuleData> upgradedSysAdminAccessRuleData = upgradeTestSession.getAccessRuleDatas(editSystemAdminName);
            for (String newRule : newRules) {
                if (!newRule.equals(AccessRulesConstants.REGULAR_VIEWENDENTITY)) {
                    assertAccessRuleDataIsPresent(upgradedSysAdminAccessRuleData, editSystemAdminName, newRule, false);
                }
            }
        } finally {
            upgradeTestSession.deleteRole(oldAuditorName);
            upgradeTestSession.deleteRole(editSystemAdminName);
            deleteRole(null, oldAuditorName);
            deleteRole(null, editSystemAdminName);
        }
    }
    
    /**
     * This test verifies that CMP aliases which refer to EEPs as names will refer to them by ID afterwards. 
     */
    @Test
    public void testUpgradeCmpConfigurationTo651()
            throws AuthorizationDeniedException, EndEntityProfileExistsException, EndEntityProfileNotFoundException {
        String aliasName = "testUpgradeCmpConfigurationTo651";
        String profileName = "testUpgradeCmpConfigurationTo651_EE_Profile";
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        endEntityProfileSession.addEndEntityProfile(alwaysAllowtoken, profileName, new EndEntityProfile());
        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(profileName);
        try {
            cmpConfiguration.addAlias(aliasName);
            cmpConfiguration.setValue(aliasName + "." + CmpConfiguration.CONFIG_RA_ENDENTITYPROFILEID, null, aliasName);
            cmpConfiguration.setValue(aliasName + "." + CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, profileName, aliasName);
            globalConfigSession.saveConfiguration(alwaysAllowtoken, cmpConfiguration);
            //Perform upgrade. 
            upgradeSession.upgrade(null, "6.5.0", false);
            //Confirm that the new value has been set.
            cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            assertEquals("End Entity Profile ID was not set during upgrade.", Integer.toString(endEntityProfileId),
                    cmpConfiguration.getRAEEProfile(aliasName));
            //Confirm that the old value was unchanged
            assertEquals("End Entity Profile ID was not set during upgrade.", profileName,
                    cmpConfiguration.getValue(aliasName + "." + CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, aliasName));

        } finally {
            cmpConfiguration = (CmpConfiguration) globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            if (cmpConfiguration.aliasExists(aliasName)) {
                cmpConfiguration.removeAlias(aliasName);
                globalConfigSession.saveConfiguration(alwaysAllowtoken, cmpConfiguration);
            }
            endEntityProfileSession.removeEndEntityProfile(alwaysAllowtoken, profileName);
        }
    }
    
    @Test
    public void upgradeTo680RoleMembers() throws AuthorizationDeniedException {
        final String roleName = TESTCLASS + " upgradeTo680RoleMembers";
        final List<AccessUserAspectData> oldAccessUserAspectDatas = Arrays.asList(
                new AccessUserAspectData(roleName, 4711, X500PrincipalAccessMatchValue.WITH_COUNTRY, AccessMatchType.TYPE_EQUALCASE, "SE"),
                new AccessUserAspectData(roleName, 4712, X500PrincipalAccessMatchValue.WITH_SERIALNUMBER, AccessMatchType.TYPE_EQUALCASEINS, "0123abcDEF")
                );
        upgradeTestSession.createRole(roleName, null, oldAccessUserAspectDatas);
        try {
            upgradeSession.upgrade(null, "6.7.0", false);
            // Post upgrade, there should exist a new RoleData object with the given rolename
            final Role newRole = roleSession.getRole(alwaysAllowtoken, null, roleName);
            final List<RoleMember> newRoleMembers = roleMemberProxySession.findRoleMemberByRoleId(newRole.getRoleId());
            assertEquals("Wrong number of role members", 2, newRoleMembers.size());
            for (final RoleMember newRoleMember : newRoleMembers) {
                assertEquals("Match value token type was not upgraded properly." , X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, newRoleMember.getTokenType());
                if (newRoleMember.getTokenIssuerId() == 4711)  {
                    assertEquals("Match value key was not upgraded properly." , X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue(), newRoleMember.getTokenMatchKey());
                    assertEquals("Match value operator was not upgraded properly." , AccessMatchType.TYPE_EQUALCASE.getNumericValue(), newRoleMember.getTokenMatchOperator());
                    assertEquals("Match value value was not upgraded properly." , "SE", newRoleMember.getTokenMatchValue());
                } else {
                    // Check that the serial number is normalized
                    assertEquals("Match value key was not upgraded properly." , X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue(), newRoleMember.getTokenMatchKey());
                    assertEquals("Match value operator was not upgraded properly." , AccessMatchType.TYPE_EQUALCASE.getNumericValue(), newRoleMember.getTokenMatchOperator());
                    assertEquals("Match value value was not upgraded properly." , "123ABCDEF", newRoleMember.getTokenMatchValue());
                }
            }
        } finally {
            //Clean up (remove legacy roles and new roles)
            upgradeTestSession.deleteRole(roleName);
            deleteRole(null, roleName);
        }
    }

    /**
     * Verifies the migration and removal of access rules. Roles with access to 
     * to /ca_functionality/basic_functions or /ca_functionality/basic_functions/activate_ca should be granted
     * corresponding access in the new rule /ca_functionality/activate_ca.
     * 
     * If upgrading from 6.6.0 or later, roles with access to /ra_functionality/view_end_entity should be granted
     * access to /ca_functionality/view_certificate.
     * 
     * Old (deprecated) rules should be removed.
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testUpgradeTo680MigrateRules() throws AuthorizationDeniedException {
        final String roleName = TESTCLASS + " upgradeTo680MigrateRules";
        final String roleName2 = TESTCLASS + " upgradeTo680MigrateRules2";
        final String roleName3 = TESTCLASS + " upgradeTo680MigrateRules3";
        final String roleName4 = TESTCLASS + " upgradeTo680MigrateRules4";
        final List<AccessRuleData> oldAccessRules = Arrays.asList(
                new AccessRuleData(roleName, UpgradeSessionRemote.REGULAR_CABASICFUNCTIONS_OLD, AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName, UpgradeSessionRemote.ROLE_PUBLICWEBUSER, AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName, AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRuleState.RULE_DECLINE, true),
                new AccessRuleData(roleName, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, true));
        final List<AccessRuleData> oldAccessRules2 = Arrays.asList(
                new AccessRuleData(roleName2, StandardRules.CAFUNCTIONALITY.resource(), AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName2, UpgradeSessionRemote.REGULAR_ACTIVATECA_OLD, AccessRuleState.RULE_DECLINE, true));
        final List<AccessRuleData> oldAcccessRules3 = Arrays.asList(
                new AccessRuleData(roleName3, UpgradeSessionRemote.REGULAR_CABASICFUNCTIONS_OLD, AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName3, UpgradeSessionRemote.REGULAR_ACTIVATECA_OLD, AccessRuleState.RULE_DECLINE, true),
                new AccessRuleData(roleName3, AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRuleState.RULE_ACCEPT, true));
        final List<AccessRuleData> oldAccessRules4 = Arrays.asList(
                new AccessRuleData(roleName4, AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName4, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_DECLINE, true));
        upgradeTestSession.createRole(roleName, oldAccessRules, null);
        upgradeTestSession.createRole(roleName2, oldAccessRules2, null);
        upgradeTestSession.createRole(roleName3, oldAcccessRules3, null);
        upgradeTestSession.createRole(roleName4, oldAccessRules4, null);
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedFromVersion("6.7.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        try {
            upgradeSession.upgrade(null, "6.7.0", false);
            final Role newRole = roleSession.getRole(alwaysAllowtoken, null, roleName);
            final Role newRole2 = roleSession.getRole(alwaysAllowtoken, null, roleName2);
            final Role newRole3 = roleSession.getRole(alwaysAllowtoken, null, roleName3);
            final Role newRole4 = roleSession.getRole(alwaysAllowtoken, null, roleName4);
            assertNotNull("Unable to retrieve role from databse", newRole);
            assertNotNull("Unable to retrieve role from databse", newRole2);
            assertNotNull("Unable to retrieve role from databse", newRole3);
            assertNotNull("Unable to retrieve role from databse", newRole4);
            // Expect normalization and minimization to do its work
            assertEquals("Unexpected number of access rules", 1, newRole.getAccessRules().size());
            assertEquals("Unexpected number of access rules", 2, newRole2.getAccessRules().size());
            assertEquals("Unexpected number of access rules", 2, newRole3.getAccessRules().size());
            assertEquals("Unexpected number of access rules", 2, newRole4.getAccessRules().size());
            // Expect the state of the deprecated rule to be unchanged in the replacing rule
            assertEquals("Unexpected access rule state", Role.STATE_ALLOW, AccessRulesHelper.hasAccessToResource(newRole.getAccessRules(),  AccessRulesConstants.REGULAR_ACTIVATECA));
            assertEquals("Unexpected access rule state", Role.STATE_DENY,  AccessRulesHelper.hasAccessToResource(newRole.getAccessRules(),  AccessRulesConstants.REGULAR_VIEWCERTIFICATE));
            assertEquals("Unexpected access rule state", Role.STATE_DENY,  AccessRulesHelper.hasAccessToResource(newRole2.getAccessRules(), AccessRulesConstants.REGULAR_ACTIVATECA));
            assertEquals("Unexpected access rule state", Role.STATE_DENY,  AccessRulesHelper.hasAccessToResource(newRole3.getAccessRules(), AccessRulesConstants.REGULAR_ACTIVATECA));
            assertEquals("Unexpected access rule state", Role.STATE_ALLOW, AccessRulesHelper.hasAccessToResource(newRole3.getAccessRules(), AccessRulesConstants.REGULAR_VIEWCERTIFICATE));
            assertEquals("Unexpected access rule state", Role.STATE_DENY,  AccessRulesHelper.hasAccessToResource(newRole4.getAccessRules(), AccessRulesConstants.REGULAR_VIEWCERTIFICATE));
        } finally {
            //Clean up (remove legacy roles and new roles)
            upgradeTestSession.deleteRole(roleName);
            upgradeTestSession.deleteRole(roleName2);
            upgradeTestSession.deleteRole(roleName3);
            upgradeTestSession.deleteRole(roleName4);
            deleteRole(null, roleName);
            deleteRole(null, roleName2);
            deleteRole(null, roleName3);
            deleteRole(null, roleName4);
        }
        // Attempt with version installed earlier than EJBCA 6.6.0 and upgraded from 6.7.0
        upgradeTestSession.createRole(roleName3, oldAcccessRules3, null);

        guc.setUpgradedFromVersion("6.5.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        try {
            upgradeSession.upgrade(null, "6.7.0", false);
            final Role newRole3 = roleSession.getRole(alwaysAllowtoken, null, roleName3);
            assertNotNull("Unable to retrieve role from databse", newRole3);
            //Since upgrade is performed from version < 6.6.0, rule state should NOT be migrated from REGULAR_VIEWENDENTITY to REGULAR_VIEWCERTIFICATE
            assertEquals("Unexpected access rule state", Role.STATE_DENY, AccessRulesHelper.hasAccessToResource(newRole3.getAccessRules(), AccessRulesConstants.REGULAR_VIEWCERTIFICATE));
        } finally {
            //Clean up (remove legacy role and new role)
            upgradeTestSession.deleteRole(roleName3);
            deleteRole(null, roleName3);
        }
    }

    /**
     * Test upgrading CAs to the 6.8.0 form of approvals, i.e. using one approval profile per approval action instead of one
     * profile for all actions. Expected behavior is that the upgraded CA should have a map containing all actions mapped to the same (previously)
     * set profile, and any entities
     * 
     */
    @Test
    public void testUpgradeCaTo680Approvals() throws CertificateParsingException, CryptoTokenOfflineException, OperatorCreationException,
            CAExistsException, AuthorizationDeniedException, ApprovalProfileExistsException, CADoesntExistsException {
        //This CA should not be assigned an approval profile on account of lacking any actions
        X509CA noActionsCa = CaTestUtils.createTestX509CA("CN=NoActions", "foo123".toCharArray(), false);
        noActionsCa.setApprovals(null);
        noActionsCa.setApprovalProfile(-1);
        noActionsCa.setApprovalSettings(new ArrayList<Integer>());
        caSession.addCA(alwaysAllowtoken, noActionsCa);

        ApprovalProfile requireTwoApprovals = new AccumulativeApprovalProfile("testUpgradeTo680Approvals");
        int requireTwoApprovalsId = approvalProfileSession.addApprovalProfile(alwaysAllowtoken, requireTwoApprovals);
        
        //This CA should be assigned a profile, and a couple of actions.  
        X509CA caWithApprovalsSet = CaTestUtils.createTestX509CA("CN=caWithApprovalsSet", "foo123".toCharArray(), false);
        caWithApprovalsSet.setApprovals(null);
        caWithApprovalsSet.setApprovalProfile(requireTwoApprovalsId);
        List<Integer> approvalSettings = new ArrayList<>(Arrays.asList(ApprovalRequestType.ACTIVATECA.getIntegerValue(), ApprovalRequestType.KEYRECOVER.getIntegerValue()));
        caWithApprovalsSet.setApprovalSettings(approvalSettings);
        caSession.addCA(alwaysAllowtoken, caWithApprovalsSet);
        
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedFromVersion("6.5.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        try {
            upgradeSession.upgrade(null, "6.7.0", false);
            //Verify that the CA without approval set merely returns an empty map
            CAInfo upgradedNoActionCa = caSession.getCAInfo(alwaysAllowtoken, noActionsCa.getCAId());
            assertTrue("CA without approvals was upgraded to have approvals", upgradedNoActionCa.getApprovals().isEmpty());
            CAInfo upgradedApprovalsCA = caSession.getCAInfo(alwaysAllowtoken, caWithApprovalsSet.getCAId());
            Map<ApprovalRequestType, Integer> approvals = upgradedApprovalsCA.getApprovals();
            assertEquals("CA with approvals for two actions did not get any approvals set.", 2, approvals.size());
            assertEquals("Approval profile was not set for action during upgrade.", Integer.valueOf(requireTwoApprovalsId), approvals.get(ApprovalRequestType.ACTIVATECA));
            assertEquals("Approval profile was not set for action during upgrade.", Integer.valueOf(requireTwoApprovalsId), approvals.get(ApprovalRequestType.KEYRECOVER));
        } finally {
            CaTestUtils.removeCa(alwaysAllowtoken, noActionsCa.getCAInfo());
            CaTestUtils.removeCa(alwaysAllowtoken, caWithApprovalsSet.getCAInfo());
            approvalProfileSession.removeApprovalProfile(alwaysAllowtoken, requireTwoApprovalsId);
        }
    }

    /**
     * Test upgrading Certificate Profiles to the 6.8.0 form of approvals, i.e. using one approval profile per approval action instead of one
     * profile for all actions. Expected behavior is that the upgraded CP should have a map containing all actions mapped to the same (previously)
     * set profile, and any entities
     * 
     */
    @Test
    public void testUpgradCertificateProfileTo680Approvals() throws AuthorizationDeniedException, CertificateProfileExistsException, ApprovalProfileExistsException {
        //This Certificate profile should not be assigned an approval profile on account of lacking any actions
        CertificateProfile noApprovals = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final String noApprovalsName = "noApprovals";
        certificateProfileSession.addCertificateProfile(alwaysAllowtoken, noApprovalsName, noApprovals);

        ApprovalProfile requireTwoApprovals = new AccumulativeApprovalProfile("testUpgradeTo680Approvals");
        int requireTwoApprovalsId = approvalProfileSession.addApprovalProfile(alwaysAllowtoken, requireTwoApprovals);
        
        //This Certificate Profile should be assigned a profile, and a couple of actions.  
        CertificateProfile withApprovals = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        withApprovals.setApprovals(null);
        withApprovals.setApprovalProfileID(requireTwoApprovalsId);
        List<Integer> approvalSettings = new ArrayList<>(Arrays.asList(ApprovalRequestType.ACTIVATECA.getIntegerValue(), ApprovalRequestType.KEYRECOVER.getIntegerValue()));
        withApprovals.setApprovalSettings(approvalSettings);
        final String withApprovalsName = "withApprovals";
        certificateProfileSession.addCertificateProfile(alwaysAllowtoken, withApprovalsName, withApprovals);

        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        guc.setUpgradedFromVersion("6.5.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        try {
            upgradeSession.upgrade(null, "6.7.0", false);
            //Verify that the CA without approval set merely returns an empty map
            CertificateProfile upgradedNoApprovals = certificateProfileSession.getCertificateProfile(noApprovalsName);
            assertTrue("Certificate Profile without approvals was upgraded to have approvals", upgradedNoApprovals.getApprovals().isEmpty());

            CertificateProfile upgradedWithApprovals = certificateProfileSession.getCertificateProfile(withApprovalsName);
            Map<ApprovalRequestType, Integer> approvals = upgradedWithApprovals.getApprovals();
            assertEquals("Certificate Profile  with approvals for two actions did not get any approvals set.", 2, approvals.size());
            assertEquals("Approval profile was not set for action during upgrade.", Integer.valueOf(requireTwoApprovalsId), approvals.get(ApprovalRequestType.ACTIVATECA));
            assertEquals("Approval profile was not set for action during upgrade.", Integer.valueOf(requireTwoApprovalsId), approvals.get(ApprovalRequestType.KEYRECOVER));
        } finally {
            certificateProfileSession.removeCertificateProfile(alwaysAllowtoken, noApprovalsName);
            certificateProfileSession.removeCertificateProfile(alwaysAllowtoken, withApprovalsName);
            approvalProfileSession.removeApprovalProfile(alwaysAllowtoken, requireTwoApprovalsId);
        }
    }

    /**
     * Tests upgrade from 6.9.0 to 6.10.1.
     * The tests expects all previous CT log selections in certificate profiles to be changed into corresponding CT Labels.
     * Additionally Each CT log should get a label set during upgrade. Previous Google logs 
     * should get the label "Mandatory", remaining logs should get the label "Unlabeled"
     * @throws CertificateProfileExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testUpgradeCtLogsTo6101() throws CertificateProfileExistsException, AuthorizationDeniedException {
        final String UNUSED_LABEL = "Unlabeled";
        final String MANDATORY_LABEL = "Mandatory";
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final String CTLOG_PUBKEY =
                "-----BEGIN PUBLIC KEY-----\n"+
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAnXBeTH4xcl2c8VBZqtfgCTa+5sc\n"+
                "wV+deHQeaRJQuM5DBYfee9TQn+mvBfYPCTbKEnMGeoYq+BpLCBYgaqV6hw==\n"+
                "-----END PUBLIC KEY-----\n";
        final byte[] pubKeyBytes = KeyTools.getBytesFromPEM(CTLOG_PUBKEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
        // Create some logs
        List<CTLogInfo> ctLogsPreUpgrade = new ArrayList<>();
        final CTLogInfo log1 = new CTLogInfo("https://one.upgradetest.com/ct/v1/", pubKeyBytes, null, 5000);
        final CTLogInfo log2 = new CTLogInfo("https://two.upgradetest.com/ct/v1/", pubKeyBytes, null, 5000);
        final CTLogInfo log3 = new CTLogInfo("https://three.upgradetest.com/ct/v1/", pubKeyBytes, null, 5000);
        final CTLogInfo log4 = new CTLogInfo("https://four.upgradetest.com/ct/v1/", pubKeyBytes, null, 5000);
        final CTLogInfo logGoogle = new CTLogInfo("https://ct.googleapis.com/upgradetest/ct/v1/", pubKeyBytes, null, 5000);
        ctLogsPreUpgrade.addAll(Arrays.asList(log1, log2, log3, log4, logGoogle));
        gc.addCTLog(log1);
        gc.addCTLog(log2);
        gc.addCTLog(log3);
        gc.addCTLog(log4);
        gc.addCTLog(logGoogle);
        globalConfigSession.saveConfiguration(alwaysAllowtoken, gc);
        final int numberOfCtLogsPreUpgrade = gc.getCTLogs().size();
        // Create certificate profile using CT Logs
        CertificateProfile profileUseCt = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final String profileUseCtName = "profileUseCt";
        profileUseCt.setUseCertificateTransparencyInCerts(true);
        profileUseCt.setEnabledCTLogs(new LinkedHashSet<Integer>(Arrays.asList(log1.getLogId(), log2.getLogId(), logGoogle.getLogId())));
        certificateProfileSession.addCertificateProfile(alwaysAllowtoken, profileUseCtName, profileUseCt);
        
        CertificateProfile profileUseCt2 = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        final String profileUseCtName2 = "profileUseCt2";
        profileUseCt2.setUseCertificateTransparencyInCerts(true);
        profileUseCt2.setEnabledCTLogs(new LinkedHashSet<Integer>(Arrays.asList(log1.getLogId(), log2.getLogId(), log3.getLogId())));
        profileUseCt2.setCtMinNonMandatoryScts(0);
        profileUseCt2.setCtMaxNonMandatoryScts(3);
        certificateProfileSession.addCertificateProfile(alwaysAllowtoken, profileUseCtName2, profileUseCt2);
        
        guc.setUpgradedFromVersion("6.9.0"); 
        globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
        try {
            // Perform upgrade 6.9.0 --> 6.10.1
            upgradeSession.upgrade(null, "6.9.0", false);
            GlobalConfiguration gcUpgraded = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            LinkedHashMap<Integer, CTLogInfo> upgradedCtLogs = gcUpgraded.getCTLogs();
            // Check if all CT Logs survived upgrade
            assertEquals("Unexpected number of CT logs. Some CT log(s) were lost during upgrade", numberOfCtLogsPreUpgrade, gc.getCTLogs().size());
            // Check if labels were translated properly
            assertEquals("Unexpected label set for CT log during upgrade", UNUSED_LABEL, upgradedCtLogs.get(log1.getLogId()).getLabel());
            assertEquals("Unexpected label set for CT log during upgrade", UNUSED_LABEL, upgradedCtLogs.get(log2.getLogId()).getLabel());
            assertEquals("Unexpected label set for CT log during upgrade", UNUSED_LABEL, upgradedCtLogs.get(log3.getLogId()).getLabel());
            assertEquals("Unexpected label set for CT log during upgrade", UNUSED_LABEL, upgradedCtLogs.get(log4.getLogId()).getLabel());
            assertEquals("Unexpected label set for CT log during upgrade", MANDATORY_LABEL, upgradedCtLogs.get(logGoogle.getLogId()).getLabel());
            // Verify that CT logs selected in certificate profile were translated to selected CT Labels
            CertificateProfile upgradedProfileUseCtName = certificateProfileSession.getCertificateProfile(profileUseCtName);
            CertificateProfile upgradedProfileUseCtName2 = certificateProfileSession.getCertificateProfile(profileUseCtName2);
            assertTrue("CT Log selected in cert profile was unselected after upgrade", upgradedProfileUseCtName.getEnabledCtLabels().contains(UNUSED_LABEL));
            assertTrue("CT Log selected in cert profile was unselected after upgrade", upgradedProfileUseCtName.getEnabledCtLabels().contains(MANDATORY_LABEL));
            assertTrue("CT Log selected in cert profile was unselected after upgrade", upgradedProfileUseCtName2.getEnabledCtLabels().contains(UNUSED_LABEL));
            assertFalse("Invalid CT label selected after upgrade", upgradedProfileUseCtName2.getEnabledCtLabels().contains(MANDATORY_LABEL));
            // Verify new SCT min / max value
            assertTrue("Minimum number of SCTs was not set to 'By validity'", upgradedProfileUseCtName.isNumberOfSctByValidity());
            assertTrue("Maximum number of SCTs was not set to 'By validity'", upgradedProfileUseCtName.isMaxNumberOfSctByValidity());
            assertTrue("Minimum number of SCTs was not set to 'By custom'", upgradedProfileUseCtName2.isNumberOfSctByCustom());
            assertTrue("Maximum number of SCTs was not set to 'By custom'", upgradedProfileUseCtName2.isMaxNumberOfSctByCustom());
            assertEquals("Minimum number of SCTs was set lower than number of selected labels after upgrade", 1, upgradedProfileUseCtName2.getCtMinScts());
            assertEquals("Maximum number of SCTs was should not have been changed during upgrade", 3, upgradedProfileUseCtName2.getCtMaxScts());
        } finally {
            // Clean up (CT logs are removed in @After)
            certificateProfileSession.removeCertificateProfile(alwaysAllowtoken, profileUseCtName);
            certificateProfileSession.removeCertificateProfile(alwaysAllowtoken, profileUseCtName2);
        }
    }

    /**
     * Tests upgrade to 6.11.0. Expected behavior is roles with access to /ra_master/invoke_api before upgrade
     * should be granted 'Allow' access to the new set of rules controlling protocol access of remote RA 
     * instances.
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testUpgradeProtocolAccess6110() throws RoleExistsException, AuthorizationDeniedException {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        String roleNameInvokeApi = "roleInvokeApi";
        String roleNameSuperAdmin = "roleSuperAdmin";
        String roleNameLowAccess = "roleLowAccess";
        Role roleInvokeApiPreUpgrade = new Role(null, roleNameInvokeApi);
        Role roleSuperAdminPreUpgrade = new Role(null, roleNameSuperAdmin);
        Role roleLowAccessPreUpgrade = new Role(null, roleNameLowAccess);
        roleInvokeApiPreUpgrade.getAccessRules().put(AccessRulesConstants.REGULAR_PEERCONNECTOR_INVOKEAPI, Role.STATE_ALLOW);
        roleSuperAdminPreUpgrade.getAccessRules().put(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW);
        roleLowAccessPreUpgrade.getAccessRules().put(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, Role.STATE_ALLOW);
        try {
            Role roleInvokeApiPersisted = roleSession.persistRole(alwaysAllowtoken, roleInvokeApiPreUpgrade);
            Role roleSuperAdminPersisted = roleSession.persistRole(alwaysAllowtoken, roleSuperAdminPreUpgrade);
            Role roleLowAccessPersisted = roleSession.persistRole(alwaysAllowtoken, roleLowAccessPreUpgrade);
            // Perform upgrade 6.10.1 --> 6.11.0
            guc.setUpgradedFromVersion("6.10.1");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            upgradeSession.upgrade(null, "6.10.1", false);
            
            Role roleInvokeApiPostUpgrade = roleSession.getRole(alwaysAllowtoken, roleInvokeApiPersisted.getRoleId());
            Role roleSuperAdminPostUpgrade = roleSession.getRole(alwaysAllowtoken, roleSuperAdminPersisted.getRoleId());
            Role roleLowAccessPostUpgrade = roleSession.getRole(alwaysAllowtoken, roleLowAccessPersisted.getRoleId());
            // Make sure roles survived upgrade at all
            assertNotNull("Role vanished during upgrade", roleInvokeApiPostUpgrade);
            assertNotNull("Role vanished during upgrade", roleSuperAdminPostUpgrade);
            assertNotNull("Role vanished during upgrade", roleLowAccessPostUpgrade);
            // Verify new and old access rules
            assertTrue("Role lost old access rules during upgrade", roleInvokeApiPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERCONNECTOR_INVOKEAPI));
            assertTrue("Denied access to new access rules", roleInvokeApiPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_CMP));
            assertTrue("Denied access to new access rules", roleInvokeApiPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_EST));
            assertTrue("Denied access to new access rules", roleInvokeApiPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_WS));
            
            assertTrue("Role lost old access rules during upgrade", roleSuperAdminPostUpgrade.hasAccessToResource(StandardRules.ROLE_ROOT.resource()));
            assertTrue("Denied access to new access rules", roleSuperAdminPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_EST));
            assertTrue("Denied access to new access rules", roleSuperAdminPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_CMP));
            assertTrue("Denied access to new access rules", roleSuperAdminPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_WS));
            
            assertTrue("Role lost old access rules during upgrade", roleLowAccessPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_RAFUNCTIONALITY));
            assertFalse("Unexpected rule allowed", roleLowAccessPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_CMP));
            assertFalse("Unexpected rule allowed", roleLowAccessPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_EST));
            assertFalse("Unexpected rule allowed", roleLowAccessPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_WS));
        } finally {
            // Clean up
            deleteRole(null, roleNameInvokeApi);
            deleteRole(null, roleNameSuperAdmin);
            deleteRole(null, roleNameLowAccess);
        }     
    }
    
    
    @Test
    public void testUpgradeOcspExtensions6120() throws Exception {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        List<String> ocspExtensionBackup = OcspConfiguration.getExtensionOids();
        // Set OCSP extensions in conf file (OcspUnid, OcspCertHash, OcspCtSct -extension)
        cesecoreConfigSession.setConfigurationValue("ocsp.extensionoid", "*2.16.578.1.16.3.2;1.3.36.8.3.13;1.3.6.1.4.1.11129.2.4.5");
        // Create test key binding and persist it
        final int cryptoTokenId = cryptoTokenManagementSession.getCryptoTokenIds(alwaysAllowtoken).get(0);
        final int internalKeyBindingId = OcspTestUtils.createInternalKeyBinding(alwaysAllowtoken, cryptoTokenId, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                "ocspExtensionUpgradeTest", "RSA2048", AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        try {
            // Perform upgrade
            guc.setUpgradedFromVersion("6.11.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            upgradeSession.upgrade(null, "6.11.0", false);
            
            // we cant use OcspCtSctListExtension.OCSP_SCTLIST_OID, 
            // because org.ejbca.core.protocol.ocsp.extension.certificatetransparency.OcspCtSctListExtension is not included in Community edition
            final String OCSP_SCTLIST_OID = "1.3.6.1.4.1.11129.2.4.5";
            
            // Verify upgraded OcspKeyBinding
            final InternalKeyBindingInfo ocspTestKeyBindingPostUpgrade = internalKeyBindingSession.getInternalKeyBindingInfo(alwaysAllowtoken, internalKeyBindingId);
            assertNotNull("Could not find ocsp key binding after upgrade", ocspTestKeyBindingPostUpgrade);
            final List<String> ocspKeyExtensionOids = ocspTestKeyBindingPostUpgrade.getOcspExtensions();
            assertEquals("Unexpected amount of extensionOids imported from ocsp.properties", 3, ocspKeyExtensionOids.size());
            assertTrue("IKB did not contain Unid extension after upgrade", ocspKeyExtensionOids.contains(OCSPUnidExtension.OCSP_UNID_OID));
            assertTrue("IKB did not contain CertHash extension after upgrade", ocspKeyExtensionOids.contains(OcspCertHashExtension.CERT_HASH_OID));
            assertTrue("IKB did not contain CtSct extension after upgrade", ocspKeyExtensionOids.contains(OCSP_SCTLIST_OID));
        } finally {
            // Delete test key binding and restore previous ocsp.extensionoid value
            internalKeyBindingSession.deleteInternalKeyBinding(alwaysAllowtoken, internalKeyBindingId);
            String ocspExtensionOidRestore = "";
            for (String extension : ocspExtensionBackup) {
                ocspExtensionOidRestore += extension + ";";
            }
            cesecoreConfigSession.setConfigurationValue("ocsp.extensionoid", ocspExtensionOidRestore);
        }
    }

    /**
     * Tests upgrade to 6.14.0. Expected behavior is roles with access to /ra_master/invoke_api before upgrade
     * should be granted 'Allow' access to the rule '/protocol/scep' controlling protocol access of remote RA 
     * instances.
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testUpgradeProtocolAccess6140() throws RoleExistsException, AuthorizationDeniedException {
        GlobalUpgradeConfiguration guc = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        String roleNameInvokeApi = "roleInvokeApi";
        String roleNameSuperAdmin = "roleSuperAdmin";
        String roleNameLowAccess = "roleLowAccess";
        Role roleInvokeApiPreUpgrade = new Role(null, roleNameInvokeApi);
        Role roleSuperAdminPreUpgrade = new Role(null, roleNameSuperAdmin);
        Role roleLowAccessPreUpgrade = new Role(null, roleNameLowAccess);
        roleInvokeApiPreUpgrade.getAccessRules().put(AccessRulesConstants.REGULAR_PEERCONNECTOR_INVOKEAPI, Role.STATE_ALLOW);
        roleSuperAdminPreUpgrade.getAccessRules().put(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW);
        roleLowAccessPreUpgrade.getAccessRules().put(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, Role.STATE_ALLOW);
        try {
            Role roleInvokeApiPersisted = roleSession.persistRole(alwaysAllowtoken, roleInvokeApiPreUpgrade);
            Role roleSuperAdminPersisted = roleSession.persistRole(alwaysAllowtoken, roleSuperAdminPreUpgrade);
            Role roleLowAccessPersisted = roleSession.persistRole(alwaysAllowtoken, roleLowAccessPreUpgrade);
            // Perform upgrade 6.13.0 --> 6.14.0
            guc.setUpgradedFromVersion("6.13.0");
            globalConfigSession.saveConfiguration(alwaysAllowtoken, guc);
            upgradeSession.upgrade(null, "6.13.0", false);
            
            Role roleInvokeApiPostUpgrade = roleSession.getRole(alwaysAllowtoken, roleInvokeApiPersisted.getRoleId());
            Role roleSuperAdminPostUpgrade = roleSession.getRole(alwaysAllowtoken, roleSuperAdminPersisted.getRoleId());
            Role roleLowAccessPostUpgrade = roleSession.getRole(alwaysAllowtoken, roleLowAccessPersisted.getRoleId());
            // Make sure roles survived upgrade at all
            assertNotNull("Role '" + roleInvokeApiPostUpgrade.getRoleName() + "' vanished during upgrade", roleInvokeApiPostUpgrade);
            assertNotNull("Role '" + roleSuperAdminPostUpgrade.getRoleName() + "' vanished during upgrade", roleSuperAdminPostUpgrade);
            assertNotNull("Role '" + roleLowAccessPostUpgrade.getRoleName() + "'  vanished during upgrade", roleLowAccessPostUpgrade);
            
            assertTrue("Role lost old access rules during upgrade", roleInvokeApiPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERCONNECTOR_INVOKEAPI));
            assertTrue("Denied access to new access rule", roleInvokeApiPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_SCEP));
            
            assertTrue("Role lost old access rules during upgrade", roleSuperAdminPostUpgrade.hasAccessToResource(StandardRules.ROLE_ROOT.resource()));
            assertTrue("Denied access to new access rule", roleSuperAdminPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_SCEP));
            
            assertTrue("Role lost old access rules during upgrade", roleLowAccessPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_RAFUNCTIONALITY));
            assertFalse("Unexpected rule allowed", roleLowAccessPostUpgrade.hasAccessToResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_SCEP));
        } finally {
            // Clean up
            deleteRole(null, roleNameInvokeApi);
            deleteRole(null, roleNameSuperAdmin);
            deleteRole(null, roleNameLowAccess);
        }     
    }
    
    /**
     * Tests upgrade to 6.15.0. Any custom certificate extension defined in the previous version should get a required flag set to true.
     * 
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testUpgradeCustomCertificateExtension6150() throws AuthorizationDeniedException {
        GlobalUpgradeConfiguration globalUpgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        
        CertificateExtension certificateExtensionOne = new BasicCertificateExtension();
        certificateExtensionOne.setCriticalFlag(true);
        certificateExtensionOne.setDisplayName("Custom Certificate Extension One");
        certificateExtensionOne.setOID("10.1.1.2");

        CertificateExtension certificateExtensionTwo = new BasicCertificateExtension();
        certificateExtensionTwo.setCriticalFlag(false);
        certificateExtensionTwo.setDisplayName("Custom Certificate Extension Two");
        certificateExtensionTwo.setOID("10.1.1.3");
        
        AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        
        availableCustomCertExtensionsConfig.addCustomCertExtension(certificateExtensionOne);
        availableCustomCertExtensionsConfig.addCustomCertExtension(certificateExtensionTwo);
        
        globalConfigSession.saveConfiguration(alwaysAllowtoken, availableCustomCertExtensionsConfig);

        // Perform upgrade 6.14.0 --> 6.15.0
        globalUpgradeConfiguration.setUpgradedFromVersion("6.14.0");
        globalConfigSession.saveConfiguration(alwaysAllowtoken, globalUpgradeConfiguration);
        upgradeSession.upgrade(null, "6.14.0", false);
        
        AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfigAfterUpgrade = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);

        for (CertificateExtension customCertificateExtension : availableCustomCertExtensionsConfigAfterUpgrade.getAllAvailableCustomCertificateExtensions()) {
            assertTrue("Required flag must be set to true after upgrade!", customCertificateExtension.isRequiredFlag());
            if (customCertificateExtension.getOID().equals("10.1.1.3")) {
                assertFalse("Critical flag for CCE with oid " + customCertificateExtension.getOID() + " must be false!", customCertificateExtension.isCriticalFlag());
            }
        }
    }
    
    @Test
    public void testExternalScriptsSetting() throws AuthorizationDeniedException, PublisherExistsException {
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
    
    
    private void deleteRole(final String nameSpace, final String roleName) {
        try {
            final Role role = roleSession.getRole(alwaysAllowtoken, null, roleName);
            if (role!=null) {
                roleSession.deleteRoleIdempotent(alwaysAllowtoken, role.getRoleId());
            }
        } catch (AuthorizationDeniedException e) {
            log.debug(e.getMessage());
        }
    }
    
    private void assertAccessRuleDataIsPresent(final List<AccessRuleData> accessRules, final String roleName, final String rule, final boolean recursive) {
        assertTrue("Role was not upgraded with rule " + rule, accessRules.contains(new AccessRuleData(roleName, rule, AccessRuleState.RULE_ACCEPT, recursive)));
    }

    private void assertAccessRuleDataIsNotPresent(final List<AccessRuleData> accessRules, final String roleName, final String rule, final boolean recursive) {
        assertFalse("Role was upgraded with rule " + rule + ", even though it shouldn't have.",
                accessRules.contains(new AccessRuleData(roleName, rule, AccessRuleState.RULE_ACCEPT, recursive)));
    }
}
