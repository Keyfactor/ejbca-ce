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
package org.ejbca.core.ejb.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.Serializable;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.approvalrequests.DummyApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.ws.BatchCreateTool;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * System tests for partitioned approval profiles 
 * 
 * @version $Id$
 *
 */
public class PartitionedApprovalProfilesTest extends CaTestCase {

    private static final String P12_FOLDER_NAME = "p12";

    private static RoleData role;
    private static int caid = getTestCAId();

    private static String reqadminusername = null;
    private static String adminusername1 = null;
    private static String adminusername2 = null;

    private static ArrayList<AccessUserAspectData> adminentities;

    private static X509Certificate reqadmincert = null;
    private static X509Certificate admincert1 = null;
    private static X509Certificate admincert2 = null;

    private static AuthenticationToken reqadmin = null;
    private static AuthenticationToken admin1 = null;
    private static AuthenticationToken admin2 = null;

    private static List<File> fileHandles = new ArrayList<File>();

    private ApprovalSessionRemote approvalSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private ApprovalExecutionSessionRemote approvalExecutionSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(ApprovalExecutionSessionRemote.class);
    private ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);

    private static final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal(ApprovalSessionTest.class.getSimpleName()));

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createTestCA();
        adminusername1 = "PartitionedApprovalProfileTest" + "1";
        adminusername2 = "PartitionedApprovalProfileTest" + "2";
        reqadminusername = "req" + "PartitionedApprovalProfileTest";

        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityManagementSessionRemote.class);

        EndEntityInformation userdata = new EndEntityInformation(adminusername1, "CN=" + adminusername1, caid, null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");
        endEntityManagementSession.addUser(alwaysAllowAuthenticationToken, userdata, true);
        EndEntityInformation userdata2 = new EndEntityInformation(adminusername2, "CN=" + adminusername2, caid, null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        userdata2.setPassword("foo123");
        endEntityManagementSession.addUser(alwaysAllowAuthenticationToken, userdata2, true);
        EndEntityInformation reqUserData = new EndEntityInformation(reqadminusername, "CN=" + reqadminusername, caid, null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_P12, 0, null);
        reqUserData.setPassword("foo123");
        endEntityManagementSession.addUser(alwaysAllowAuthenticationToken, reqUserData, true);
        String roleName = PartitionedApprovalProfilesTest.class.getSimpleName();
        RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        role = roleAccessSessionRemote.findRole(roleName);
        RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
        if (role == null) {
            role = roleManagementSession.create(alwaysAllowAuthenticationToken, roleName);
        }
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(roleName, AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(roleName, StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, accessRules);
        adminentities = new ArrayList<AccessUserAspectData>();
        adminentities.add(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername1));
        adminentities.add(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername2));
        adminentities.add(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, reqadminusername));
        roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, roleAccessSessionRemote.findRole(roleName), adminentities);
        AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
        accessControlSession.forceCacheExpire();

        fileHandles.addAll(BatchCreateTool.createAllNew(alwaysAllowAuthenticationToken, new File(P12_FOLDER_NAME)));

        CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        admincert1 = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminusername1)).iterator()
                .next();
        admincert2 = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(adminusername2)).iterator()
                .next();
        reqadmincert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(reqadminusername))
                .iterator().next();
        SimpleAuthenticationProviderSessionRemote simpleAuthenticationProvider = EjbRemoteHelper.INSTANCE
                .getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        admin1 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert1));
        admin2 = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(admincert2));
        reqadmin = simpleAuthenticationProvider.authenticate(makeAuthenticationSubject(reqadmincert));
    }

    @AfterClass
    public static void afterClass() throws Exception {
        for (File file : fileHandles) {
            FileTools.delete(file);
        }
        removeTestCA();
        RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
        roleManagementSession.remove(alwaysAllowAuthenticationToken, role);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityManagementSessionRemote.class);
        endEntityManagementSession.deleteUser(alwaysAllowAuthenticationToken, adminusername1);
        endEntityManagementSession.deleteUser(alwaysAllowAuthenticationToken, adminusername2);
        endEntityManagementSession.deleteUser(alwaysAllowAuthenticationToken, reqadminusername);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        internalCertificateStoreSession.removeCertificate(admincert1);
        internalCertificateStoreSession.removeCertificate(admincert2);
        internalCertificateStoreSession.removeCertificate(reqadmincert);
    }

    private static AuthenticationSubject makeAuthenticationSubject(X509Certificate certificate) {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(certificate.getSubjectX500Principal());
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        return new AuthenticationSubject(principals, credentials);
    }

    /**
     * The most vanilla of tests
     */
    @Test
    public void testSingleStepSinglePartition() throws AuthorizationDeniedException, ApprovalProfileExistsException, ApprovalException,
            ApprovalRequestExpiredException, ApprovalRequestExecutionException, AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException {
        ApprovalProfile singleStepPartitionProfile = new PartitionedApprovalProfile("testSingleSequenceSinglePartition");
        ApprovalStep executionStep = singleStepPartitionProfile.getStep(PartitionedApprovalProfile.EXECUTION_STEP_ID);
        ApprovalPartition singlePartition = executionStep.getPartitions().values().iterator().next();
        List<RoleInformation> roles = new ArrayList<>();
        //Add admin1 as an approving admin to the partition
        RoleInformation admin1RoleInfo =  new RoleInformation(1, "admin1", Arrays.asList(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername1)));
        roles.add(admin1RoleInfo);
        DynamicUiProperty<? extends Serializable> rolesProperty = new DynamicUiProperty<>(
                PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, admin1RoleInfo, roles);
        rolesProperty.setValuesGeneric(new ArrayList<RoleInformation>(Arrays.asList(admin1RoleInfo)));
        rolesProperty.setHasMultipleValues(true);
        singleStepPartitionProfile.addPropertyToPartition(executionStep.getStepIdentifier(), singlePartition.getPartitionIdentifier(), rolesProperty);
        int approvalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowAuthenticationToken,
                singleStepPartitionProfile);
        singleStepPartitionProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
        
        DummyApprovalRequest executableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, true,
                singleStepPartitionProfile);
        approvalSessionRemote.addApprovalRequest(admin1, executableRequest);
        try {
            List<ApprovalDataVO> resultList = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId());
            assertEquals(1, resultList.size());
            ApprovalDataVO unexecutedApproval = resultList.get(0);
            assertEquals("Approval should not be executed yet.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, unexecutedApproval.getStatus());
            
            //Approval specifies incorrect step/partition
            Approval wrongSteps = new Approval("wrongSteps", 1, 1);
            try {
                approvalExecutionSessionRemote.approve(admin1, executableRequest.generateApprovalId(), wrongSteps);
                fail("Approval should not have been executed with an incorrect sequence.");
            } catch (AuthorizationDeniedException e) {
                //NOPMD: Expected result.
            }
            assertEquals("Approval should not have been executed with an incorrect sequence.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                    approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0).getStatus());
            
            //Another attempt. Right step/approval, but the wrong admin
            Approval wrongAdmin = new Approval("wrongAdmin", executionStep.getStepIdentifier(), singlePartition.getPartitionIdentifier());
            try {
                approvalExecutionSessionRemote.approve(admin2, executableRequest.generateApprovalId(), wrongAdmin);
                fail("Approval should not have been executed with an incorrect sequence.");
            } catch (AuthorizationDeniedException e) {
                //NOPMD: Expected result.
            }
            assertEquals("Approval should not have been executed with an incorrect sequence.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                    approvalSessionRemote.findApprovalDataVO(admin2, executableRequest.generateApprovalId()).get(0).getStatus());
            
            
            Approval correctApproval = new Approval("correctApproval", executionStep.getStepIdentifier(), singlePartition.getPartitionIdentifier());
            approvalExecutionSessionRemote.approve(admin1, executableRequest.generateApprovalId(), correctApproval);
            ApprovalDataVO executedResult = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0);
            assertEquals("Approval should have been executed.", ApprovalDataVO.STATUS_EXECUTED, executedResult.getStatus());
        } finally {
            List<ApprovalDataVO> approvalsToDelete = approvalSessionRemote.findApprovalDataVO(alwaysAllowAuthenticationToken,
                    executableRequest.generateApprovalId());
            for (ApprovalDataVO approvalDataVO : approvalsToDelete) {
                approvalSessionRemote.removeApprovalRequest(admin1, approvalDataVO.getId());
            }
            approvalProfileSession.removeApprovalProfile(alwaysAllowAuthenticationToken, approvalProfileId);
        }

    }
    
    /**
     * A slightly less vanilla test: 
     *  * Two steps with one partition each. 
     *  * admin1 has access to the first step, admin2 to the 2nd. 
     *  * admin2 may not approve their step before admin1 has approved theirs. 
     *  * admin1 may not approve the 2nd step
     *  * request should execute after the 2nd step 
     */
    @Test
    public void testTwoStepsSinglePartition() throws AuthorizationDeniedException, ApprovalProfileExistsException, ApprovalException,
            ApprovalRequestExpiredException, ApprovalRequestExecutionException, AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException {
        ApprovalProfile doubleSequencenProfile = new PartitionedApprovalProfile("testDoubleStepSinglePartition");
        doubleSequencenProfile.addStepFirst();
        
        ApprovalStep firstStep = doubleSequencenProfile.getFirstStep();
        ApprovalPartition firstStepPartition = firstStep.getPartitions().values().iterator().next();
        List<RoleInformation> roles = new ArrayList<>();
        //Add admin1 as an approving admin to the partition
        RoleInformation admin1RoleInfo =  new RoleInformation(1, "admin1", Arrays.asList(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername1)));
        roles.add(admin1RoleInfo);
        DynamicUiProperty<? extends Serializable> firstrolesProperty = new DynamicUiProperty<>(
                PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, admin1RoleInfo, roles);
        firstrolesProperty.setValuesGeneric(new ArrayList<RoleInformation>(Arrays.asList(admin1RoleInfo)));
        firstrolesProperty.setHasMultipleValues(true);
        doubleSequencenProfile.addPropertyToPartition(firstStep.getStepIdentifier(), firstStepPartition.getPartitionIdentifier(), firstrolesProperty);
             
        ApprovalStep secondStep = doubleSequencenProfile.getStep(firstStep.getNextStep());
        ApprovalPartition secondStepPartition = secondStep.getPartitions().values().iterator().next();
        roles = new ArrayList<>();
        //Add admin1 as an approving admin to the partition
        RoleInformation admin2RoleInfo =  new RoleInformation(2, "admin2", Arrays.asList(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername2)));
        roles.add(admin1RoleInfo);
        DynamicUiProperty<? extends Serializable> secondRoleProperty = new DynamicUiProperty<>(
                PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, admin1RoleInfo, roles);
        secondRoleProperty.setValuesGeneric(new ArrayList<RoleInformation>(Arrays.asList(admin2RoleInfo)));
        secondRoleProperty.setHasMultipleValues(true);
        doubleSequencenProfile.addPropertyToPartition(secondStep.getStepIdentifier(), secondStepPartition.getPartitionIdentifier(), secondRoleProperty);
            
        int approvalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowAuthenticationToken, doubleSequencenProfile);
        doubleSequencenProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
    
        DummyApprovalRequest executableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, true,
                doubleSequencenProfile);
        approvalSessionRemote.addApprovalRequest(admin1, executableRequest);
        try {
            List<ApprovalDataVO> resultList = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId());
            assertEquals(1, resultList.size());
            ApprovalDataVO unexecutedApproval = resultList.get(0);
            assertEquals("Approval should not be executed yet.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, unexecutedApproval.getStatus());
            Approval secondStepApproval = new Approval("secondStepApproval", secondStep.getStepIdentifier(), secondStepPartition.getPartitionIdentifier());
            try {
                approvalExecutionSessionRemote.approve(admin2, executableRequest.generateApprovalId(), secondStepApproval);
                fail("Approval should not have been executed with an incorrect sequence.");
            } catch (AuthorizationDeniedException e) {
                //NOPMD: Expected:
            }
            assertEquals("Approval should not have been executed with an incorrect sequence.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                    approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0).getStatus());
            Approval firstStepApproval = new Approval("firstStepApproval", firstStep.getStepIdentifier(), firstStepPartition.getPartitionIdentifier());
            approvalExecutionSessionRemote.approve(admin1, executableRequest.generateApprovalId(), firstStepApproval);
            assertEquals("Approval should not have been executed after only one approval.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                    approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0).getStatus());
            
            approvalExecutionSessionRemote.approve(admin2, executableRequest.generateApprovalId(), secondStepApproval);
            ApprovalDataVO executedResult = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0);
            assertEquals("Approval should have been executed.", ApprovalDataVO.STATUS_EXECUTED, executedResult.getStatus());
        } finally {
            List<ApprovalDataVO> approvalsToDelete = approvalSessionRemote.findApprovalDataVO(alwaysAllowAuthenticationToken,
                    executableRequest.generateApprovalId());
            for (ApprovalDataVO approvalDataVO : approvalsToDelete) {
                approvalSessionRemote.removeApprovalRequest(admin1, approvalDataVO.getId());
            }
            approvalProfileSession.removeApprovalProfile(alwaysAllowAuthenticationToken, approvalProfileId);
        }

    }
    
    /**
     * A slightly less vanilla test: 
     *  * Two steps with one partition each. 
     *  * admin1 has access to the first partition, admin2 to the 2nd. 
     *  * Test should execute after both partitions have been fulfilled
     */
    @Test
    public void testOneStepsTwoPartitions() throws AuthorizationDeniedException, ApprovalProfileExistsException, ApprovalException,
            ApprovalRequestExpiredException, ApprovalRequestExecutionException, AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException {
        ApprovalProfile doubleSequencenProfile = new PartitionedApprovalProfile("testDoubleStepSinglePartition");        
        ApprovalStep step = doubleSequencenProfile.getFirstStep();
        ApprovalPartition firstPartition = step.getPartitions().values().iterator().next();
        ApprovalPartition secondPartition = step.addPartition();
        List<RoleInformation> roles = new ArrayList<>();
        //Add admin1 as an approving admin to the partition
        RoleInformation admin1RoleInfo =  new RoleInformation(1, "admin1", Arrays.asList(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername1)));
        roles.add(admin1RoleInfo);
        DynamicUiProperty<? extends Serializable> firstrolesProperty = new DynamicUiProperty<>(
                PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, admin1RoleInfo, roles);
        firstrolesProperty.setValuesGeneric(new ArrayList<RoleInformation>(Arrays.asList(admin1RoleInfo)));
        firstrolesProperty.setHasMultipleValues(true);
        doubleSequencenProfile.addPropertyToPartition(step.getStepIdentifier(), firstPartition.getPartitionIdentifier(), firstrolesProperty);
        //Add admin2 as an approving admin to the partition
        RoleInformation admin2RoleInfo =  new RoleInformation(1, "admin2", Arrays.asList(new AccessUserAspectData(role.getRoleName(), caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASEINS, adminusername2)));
        roles.add(admin2RoleInfo);
        DynamicUiProperty<? extends Serializable> secondrolesProperty = new DynamicUiProperty<>(
                PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, admin2RoleInfo, roles);
        secondrolesProperty.setValuesGeneric(new ArrayList<RoleInformation>(Arrays.asList(admin2RoleInfo)));
        secondrolesProperty.setHasMultipleValues(true);
        doubleSequencenProfile.addPropertyToPartition(step.getStepIdentifier(), secondPartition.getPartitionIdentifier(), secondrolesProperty);   
        int approvalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowAuthenticationToken, doubleSequencenProfile);
        doubleSequencenProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
        DummyApprovalRequest executableRequest = new DummyApprovalRequest(reqadmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, true,
                doubleSequencenProfile);
        approvalSessionRemote.addApprovalRequest(admin1, executableRequest);
        try {
            List<ApprovalDataVO> resultList = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId());
            assertEquals(1, resultList.size());
            ApprovalDataVO unexecutedApproval = resultList.get(0);
            assertEquals("Approval should not be executed yet.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, unexecutedApproval.getStatus());
            Approval secondPartitionApproval = new Approval("secondPartitionApproval", step.getStepIdentifier(), secondPartition.getPartitionIdentifier());
            approvalExecutionSessionRemote.approve(admin2, executableRequest.generateApprovalId(), secondPartitionApproval);
            assertEquals("Approval should not be executed yet.", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                    approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0).getStatus());
            Approval firstPartitionApproval = new Approval("firstPartitionApproval", step.getStepIdentifier(), firstPartition.getPartitionIdentifier());
            approvalExecutionSessionRemote.approve(admin1, executableRequest.generateApprovalId(), firstPartitionApproval);
            ApprovalDataVO executedResult = approvalSessionRemote.findApprovalDataVO(admin1, executableRequest.generateApprovalId()).get(0);
            assertEquals("Approval should have been executed.", ApprovalDataVO.STATUS_EXECUTED, executedResult.getStatus());
        } finally {
            List<ApprovalDataVO> approvalsToDelete = approvalSessionRemote.findApprovalDataVO(alwaysAllowAuthenticationToken,
                    executableRequest.generateApprovalId());
            for (ApprovalDataVO approvalDataVO : approvalsToDelete) {
                approvalSessionRemote.removeApprovalRequest(admin1, approvalDataVO.getId());
            }
            approvalProfileSession.removeApprovalProfile(alwaysAllowAuthenticationToken, approvalProfileId);
        }

    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}
