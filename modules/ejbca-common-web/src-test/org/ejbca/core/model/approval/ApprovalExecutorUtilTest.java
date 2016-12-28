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

package org.ejbca.core.model.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class ApprovalExecutorUtilTest {

    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalExecutorUtilTest"));
    
    @Before
	public void setUp() throws Exception {
	}

    @Test
	public void testNoOfApprovals() throws PropertyValidationException {
		int numOfApprovalsRequired = 1;
		AccumulativeApprovalProfile nrOfApprovalsApprovalProfile = new AccumulativeApprovalProfile("nrOfApprovalApprovalProfile");
		nrOfApprovalsApprovalProfile.initialize();
		nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(numOfApprovalsRequired);
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, 
		        EndEntityConstants.STATUS_NEW, admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);		
		numOfApprovalsRequired = 0;
		nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(numOfApprovalsRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_NEW, admin, 
		        null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);		
	}
	
    @Test
	public void testGloballyExcludedClasses() throws PropertyValidationException {
		int numOfApprovalsRequired = 1;
		AccumulativeApprovalProfile nrOfApprovalsApprovalProfile = new AccumulativeApprovalProfile("testGloballyExcludedClasses");
	    nrOfApprovalsApprovalProfile.initialize();
		nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(numOfApprovalsRequired);
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, 
		        EndEntityConstants.STATUS_NEW, admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);
		ApprovalJunitHelper.JunitApprovalExecutorUtil1.init();
		approvalRequired = ApprovalJunitHelper.JunitApprovalExecutorUtil1.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ApprovalJunitHelper.JunitApprovalExecutorUtil2.init();
		approvalRequired = ApprovalJunitHelper.JunitApprovalExecutorUtil2.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ApprovalJunitHelper.JunitApprovalExecutorUtil3.init();
		approvalRequired = ApprovalJunitHelper.JunitApprovalExecutorUtil3.requireApproval(ar, null);   
		assertTrue(approvalRequired);
	}
	
    @Test
	public void testOverridableClassNames() throws PropertyValidationException {
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS = {
			new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeUser"),
			new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeCert"),
			new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","unrevokeCert"),
			new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
			new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
			new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
		};

		int numOfApprovalsRequired = 1;
		AccumulativeApprovalProfile nrOfApprovalsApprovalProfile = new AccumulativeApprovalProfile("nrOfApprovalApprovalProfile");
		nrOfApprovalsApprovalProfile.initialize();
		nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(numOfApprovalsRequired);
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, 
		        EndEntityConstants.STATUS_NEW, admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS);   
		assertTrue(approvalRequired);
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS1 = {
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeUser"),
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeCert"),
				new ApprovalOveradableClassName("org.ejbca.core.model.approval.ApprovalExecutorUtilTest","foo"),
				new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
				new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
				new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
			};		
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_NEW, 
		        admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS1);   
		assertTrue(approvalRequired);
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS2 = {
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeUser"),
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeCert"),
				new ApprovalOveradableClassName("org.ejbca.core.model.approval.ApprovalExecutorUtilTest",null),
				new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
				new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
				new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
			};		
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_NEW, 
		        admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS2);   
		assertFalse(approvalRequired);
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS3 = {
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeUser"),
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeCert"),
				new ApprovalOveradableClassName("org.ejbca.core.model.approval.ApprovalExecutorUtilTest","testOverridableClassNames"),
				new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
				new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
				new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
			};
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_NEW, 
		        admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS3);   
		assertFalse(approvalRequired);

	}
	
    @Test
	public void testAllowedTransitions() throws PropertyValidationException {
		int numOfApprovalsRequired = 1;
		AccumulativeApprovalProfile nrOfApprovalsApprovalProfile = new AccumulativeApprovalProfile("nrOfApprovalApprovalProfile");
		nrOfApprovalsApprovalProfile.initialize();
		nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(numOfApprovalsRequired);
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_NEW, 
		        EndEntityConstants.STATUS_INPROCESS, admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_GENERATED, EndEntityConstants.STATUS_NEW, 
		        admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_INPROCESS, EndEntityConstants.STATUS_GENERATED, 
		        admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_INPROCESS, EndEntityConstants.STATUS_FAILED, 
		        admin, null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", EndEntityConstants.STATUS_REVOKED, EndEntityConstants.STATUS_NEW, admin, 
		        null, 1, 1, nrOfApprovalsApprovalProfile);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);
		
	}
    
    @Test
    public void testAccumulativeApprovalProfile() throws Exception {
        final String approvalProfileName = "testAccumulativeApprovalProfile";
        final AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
        approvalProfile.initialize();
        approvalProfile.setNumberOfApprovalsRequired(0);
        assertEquals(0, approvalProfile.getNumberOfApprovalsRequired());
        
        RevocationApprovalRequest revReq = new RevocationApprovalRequest(null, "", "", 0, null, 0, 0, approvalProfile);
        assertFalse(ApprovalExecutorUtil.requireApproval(revReq, null));
        AddEndEntityApprovalRequest addReq = new AddEndEntityApprovalRequest(null, false, null, "", 0, 0, approvalProfile);
        assertFalse(ApprovalExecutorUtil.requireApproval(addReq, null));
        
        approvalProfile.setNumberOfApprovalsRequired(1);
        assertEquals(1, approvalProfile.getNumberOfApprovalsRequired());
        revReq = new RevocationApprovalRequest(null, "", "", 0, null, 0, 0, approvalProfile);
        assertTrue(ApprovalExecutorUtil.requireApproval(revReq, null));
    }
}
