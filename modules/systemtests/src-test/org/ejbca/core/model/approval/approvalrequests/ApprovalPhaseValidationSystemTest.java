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
package org.ejbca.core.model.approval.approvalrequests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.validation.CouldNotRemoveKeyValidatorException;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.KeyValidationFailedActions;
import org.cesecore.keys.validation.KeyValidatorProxySessionRemote;
import org.cesecore.keys.validation.ValidationResult;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.validation.DomainBlacklistValidator;
import org.ejbca.core.model.validation.domainblacklist.DomainBlacklistExactMatchChecker;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test of approval requests with a Validator with {@link IssuancePhase#APPROVAL_VALIDATION}.
 *
 * @version $Id$
 */
public class ApprovalPhaseValidationSystemTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(ApprovalPhaseValidationSystemTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalPhaseValidationSystemTest"));

    private static final String TEST_APPROVALPROFILE = "ApprovalPhaseValidationSystemTest_AP";
    private static final String TEST_CERTIFICATEPROFILE = "ApprovalPhaseValidationSystemTest_CP";
    private static final String TEST_ENDENTITYPROFILE = "ApprovalPhaseValidationSystemTest_EEP";
    private static final String TEST_VALIDATOR = "ApprovalPhaseValidationSystemTest_VAL";
    private static final String TEST_ENDENTITY = "ApprovalPhaseValidationSystemTest_EE";
    private static final int TEST_APPROVAL_HASH = -1936630207; // in order to clean up old data before test, may need to be updated if test is changed

    private static final String BLACKLISTED_DOMAIN = "example.net";

    
    private CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    private KeyValidatorProxySessionRemote validatorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);

    private int certificateProfileId;
    private int endEntityProfileId;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        log.trace(">setUp");
        super.setUp();
        cleanup();
        initialize();
        log.trace("<setUp");
    }

    @Override
    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown");
        super.tearDown();
        cleanup();
        log.trace("<tearDown");
    }

    private void cleanup() throws AuthorizationDeniedException {
        log.trace(">cleanup");
        final List<ApprovalDataVO> advos = approvalSession.findApprovalDataVO(TEST_APPROVAL_HASH);
        for (final ApprovalDataVO advo : advos) {
            approvalSession.removeApprovalRequest(admin, advo.getId());
        }
        try {
            validatorSession.removeKeyValidator(admin, TEST_VALIDATOR);
        } catch (CouldNotRemoveKeyValidatorException e) {
            log.info("Could not clean up validator", e);
        }
        endEntityProfileSession.removeEndEntityProfile(admin, TEST_ENDENTITYPROFILE);
        certificateProfileSession.removeCertificateProfile(admin, TEST_CERTIFICATEPROFILE);
        final Map<Integer, String> approvalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
        for (final Entry<Integer, String> approvalProfile : approvalProfiles.entrySet()) {
            if (TEST_APPROVALPROFILE.equals(approvalProfile.getValue())) {
                approvalProfileSession.removeApprovalProfile(admin, approvalProfile.getKey());
            }
        }
        try {
            endEntityManagementSession.deleteUser(admin, TEST_ENDENTITY);
        } catch (CouldNotRemoveEndEntityException e) {
            log.info("Could not clean up end entity", e);
        } catch (NoSuchEndEntityException e) {
            // NOPMD Ignored
        }
        log.trace("<cleanup");
    }

    private void initialize() throws Exception {
        log.trace(">initialize");
        final int caId = getTestCAId();
        // Create Approval Profile
        final AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(TEST_APPROVALPROFILE);
        approvalProfile.setNumberOfApprovalsRequired(1);
        final int approvalProfileId = approvalProfileSession.addApprovalProfile(admin, approvalProfile);
        // Create Certificate Profile
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);
        final Map<ApprovalRequestType,Integer> approvalSettings = new LinkedHashMap<>();
        approvalSettings.put(ApprovalRequestType.ADDEDITENDENTITY, approvalProfileId);
        certificateProfile.setApprovals(approvalSettings);
        certificateProfile.setAvailableCAs(new ArrayList<>(Arrays.asList(caId)));
        certificateProfileId = certificateProfileSession.addCertificateProfile(admin, TEST_CERTIFICATEPROFILE, certificateProfile);
        // Create End Entity Profile
        final EndEntityProfile endEntityProfile = new EndEntityProfile();
        endEntityProfile.setDefaultCA(caId);
        endEntityProfile.setAvailableCAs(new ArrayList<>(Arrays.asList(caId)));
        endEntityProfile.setDefaultCertificateProfile(certificateProfileId);
        endEntityProfile.setAvailableCertificateProfileIds(new ArrayList<>(Arrays.asList(certificateProfileId)));
        endEntityProfile.addField(DnComponents.COMMONNAME);
        endEntityProfile.addField(DnComponents.DNSNAME);
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(admin, TEST_ENDENTITYPROFILE, endEntityProfile);
        // Create validator
        final DomainBlacklistValidator validator = new DomainBlacklistValidator();
        validator.setAllCertificateProfileIds(false);
        validator.setCertificateProfileIds(new ArrayList<>(Arrays.asList(certificateProfileId)));
        validator.setFailedAction(KeyValidationFailedActions.LOG_INFO.getIndex());
        validator.setNotApplicableAction(KeyValidationFailedActions.LOG_INFO.getIndex());
        validator.setPhase(IssuancePhase.APPROVAL_VALIDATION.getIndex());
        validator.setNormalizations(Collections.emptyList());
        validator.setChecks(new ArrayList<>(Arrays.asList(DomainBlacklistExactMatchChecker.class.getName())));
        validator.setBlacklist(new HashSet<>(Arrays.asList(BLACKLISTED_DOMAIN)));
        validator.setProfileName(TEST_VALIDATOR);
        final int validatorId = validatorSession.addKeyValidator(admin, validator);
        // Enabled validator in CA
        final CAInfo caInfo = caSession.getCAInfo(admin, caId);
        caInfo.setValidators(new ArrayList<>(Arrays.asList(validatorId)));
        caAdminSession.editCA(admin, caInfo);
        log.trace("<initialize");
    }

    @Override
    public String getRoleName() {
        return "ApprovalPhaseValidationSystemTest";
    }

    /**
     * Performs an addUser call that requires approval, and checks that validation has been performed of the DNSNAME field in the End Entity SAN.
     * @throws Exception
     */
    @Test
    public void failedValidationInApprovalPhase() throws Exception {
        log.trace(">validationInApprovalPhase");
        // given
        final EndEntityInformation endEntity = new EndEntityInformation();
        endEntity.setUsername(TEST_ENDENTITY);
        endEntity.setPassword("foo123");
        endEntity.setCAId(getTestCAId());
        endEntity.setCertificateProfileId(certificateProfileId);
        endEntity.setEndEntityProfileId(endEntityProfileId);
        endEntity.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
        endEntity.setDN("CN=" + TEST_ENDENTITY);
        endEntity.setSubjectAltName("DNSNAME=" + BLACKLISTED_DOMAIN);
        endEntity.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        // when
        final int requestId;
        try {
            endEntityManagementSession.addUser(admin, endEntity, false);
            fail("Certificate Profile is configured to require approval. This should throw");
            throw new IllegalStateException(); // make compiler happy
        } catch (WaitingForApprovalException e) {
            requestId = e.getRequestId();
        }
        // then
        try {
            final ApprovalDataVO advo = approvalSession.findApprovalDataByRequestId(requestId);
            final ApprovalRequest approvalRequest = advo.getApprovalRequest();
            final List<ValidationResult> validationResults = approvalRequest.getValidationResults();
            assertNotNull("Approval request should contain ValidationResults, not null.", validationResults);
            assertEquals("Wrong number of ValidationResults.", 1, validationResults.size());
            final ValidationResult validationResult = validationResults.get(0);
            assertFalse("Validation should be unsuccessful", validationResult.isSuccessful());
            assertTrue("Message should contain failed domain name.", validationResult.getMessage().contains(BLACKLISTED_DOMAIN));
            // TEST_APPROVAL_HASH needs to match or cleanup before the test won't work.
            assertEquals("Please update TEST_APPROVAL_HASH (to " + advo.getApprovalId() + ") in the test.", advo.getApprovalId(), TEST_APPROVAL_HASH);
        } finally {
            approvalSession.removeApprovalRequest(admin, requestId);
        }
        log.trace("<validationInApprovalPhase");
    }

    /**
     * Performs an addUser call that requires approval, but is successfully validated. 
     * @throws Exception
     */
    @Test
    public void successfulValidationInApprovalPhase() throws Exception {
        log.trace(">validationInApprovalPhase");
        // given
        final EndEntityInformation endEntity = new EndEntityInformation();
        endEntity.setUsername(TEST_ENDENTITY);
        endEntity.setPassword("foo123");
        endEntity.setCAId(getTestCAId());
        endEntity.setCertificateProfileId(certificateProfileId);
        endEntity.setEndEntityProfileId(endEntityProfileId);
        endEntity.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
        endEntity.setDN("CN=" + TEST_ENDENTITY);
        endEntity.setSubjectAltName("DNSNAME=good.example.org"); // allowed domain
        endEntity.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        // when
        final int requestId;
        try {
            endEntityManagementSession.addUser(admin, endEntity, false);
            fail("Certificate Profile is configured to require approval. This should throw");
            throw new IllegalStateException(); // make compiler happy
        } catch (WaitingForApprovalException e) {
            requestId = e.getRequestId();
        }
        // then
        try {
            final ApprovalDataVO advo = approvalSession.findApprovalDataByRequestId(requestId);
            final ApprovalRequest approvalRequest = advo.getApprovalRequest();
            final List<ValidationResult> validationResults = approvalRequest.getValidationResults();
            assertNotNull("Approval request should contain ValidationResults, not null.", validationResults);
            assertEquals("There should be no validation results.", 0, validationResults.size());
            // TEST_APPROVAL_HASH needs to match or cleanup before the test won't work.
            assertEquals("Please update TEST_APPROVAL_HASH (to " + advo.getApprovalId() + ") in the test.", advo.getApprovalId(), TEST_APPROVAL_HASH);
        } finally {
            approvalSession.removeApprovalRequest(admin, requestId);
        }
        log.trace("<validationInApprovalPhase");
    }

}
