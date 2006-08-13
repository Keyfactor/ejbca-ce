package se.anatom.ejbca.approval;

import junit.framework.TestCase;

import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;

public class TestApprovalExecutorUtil extends TestCase {

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
				new ApprovalOveradableClassName("se.anatom.ejbca.approval.TestApprovalExecutorUtil","foo"),
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
				new ApprovalOveradableClassName("se.anatom.ejbca.approval.TestApprovalExecutorUtil",null),
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
				new ApprovalOveradableClassName("se.anatom.ejbca.approval.TestApprovalExecutorUtil","testOverridableClassNames"),
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
