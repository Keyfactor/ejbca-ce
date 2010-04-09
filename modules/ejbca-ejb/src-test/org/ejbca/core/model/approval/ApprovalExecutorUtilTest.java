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

package org.ejbca.core.model.approval;

import junit.framework.TestCase;

import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;

/**
 * @version $Id$
 */
public class ApprovalExecutorUtilTest extends TestCase {

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    
	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void testNoOfApprovals() {
		int numOfApprovalsRequired = 1;
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);		
		numOfApprovalsRequired = 0;
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);		
	}
	
	public void testGloballyExcludedClasses() {
		int numOfApprovalsRequired = 1;
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
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
	
	public void testOverridableClassNames() {
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS = {
			new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeUser"),
			new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeCert"),
			new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","unrevokeCert"),
			new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
			new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
			new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
		};

		int numOfApprovalsRequired = 1;
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS);   
		assertTrue(approvalRequired);
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS1 = {
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeUser"),
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeCert"),
				new ApprovalOveradableClassName("org.ejbca.core.model.approval.ApprovalExecutorUtilTest","foo"),
				new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
				new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
				new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
			};		
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS1);   
		assertTrue(approvalRequired);
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS2 = {
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeUser"),
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeCert"),
				new ApprovalOveradableClassName("org.ejbca.core.model.approval.ApprovalExecutorUtilTest",null),
				new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
				new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
				new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
			};		
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS2);   
		assertFalse(approvalRequired);
		ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS3 = {
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeUser"),
				new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.LocalUserAdminSessionBean","revokeCert"),
				new ApprovalOveradableClassName("org.ejbca.core.model.approval.ApprovalExecutorUtilTest","testOverridableClassNames"),
				new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
				new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
				new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
			};		
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS3);   
		assertFalse(approvalRequired);

	}
	
	public void testAllowedTransitions() {
		int numOfApprovalsRequired = 1;
		ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_NEW, UserDataConstants.STATUS_INPROCESS, admin, null, numOfApprovalsRequired, 1, 1);
		boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_GENERATED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_INPROCESS, UserDataConstants.STATUS_GENERATED, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_INPROCESS, UserDataConstants.STATUS_FAILED, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertFalse(approvalRequired);
		ar = new ChangeStatusEndEntityApprovalRequest("foo", UserDataConstants.STATUS_REVOKED, UserDataConstants.STATUS_NEW, admin, null, numOfApprovalsRequired, 1, 1);
		approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);   
		assertTrue(approvalRequired);
		
	}
}
