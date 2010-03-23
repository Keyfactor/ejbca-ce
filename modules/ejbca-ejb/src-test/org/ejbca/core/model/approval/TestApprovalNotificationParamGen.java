package org.ejbca.core.model.approval;

import java.util.Date;

import junit.framework.TestCase;

/** Tests some substitution variables for approval notifications
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class TestApprovalNotificationParamGen extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();		
	}
	
	public void testInterpolate(){
		Date now = new Date();
		int id = 123;
		String approvalTypeText = "testaproval";
		int numAppr = 2;
		String approvalURL = "http://approval.test/";
		String approveComment = "Comment";
		String requestAdminUsername = "username";
		String requestAdminDN = "CN=user,O=Org,C=SE";
		String approvalAdminUsername = "approvalUsername";
		String approvalAdminDN = "CN=approvaluser,O=Org,C=SE";
        ApprovalNotificationParamGen paramGen = new ApprovalNotificationParamGen(now,id,approvalTypeText,numAppr,
                approvalURL, approveComment, requestAdminUsername,
                requestAdminDN,approvalAdminUsername,approvalAdminDN);
		
        String msg = paramGen.interpolate("${approvalRequest.ID} ${approvalRequest.TYPE} ${requestAdmin.CN} ${requestAdmin.O} ${approvalRequest.APPROVALSLEFT} ${approvalRequest.APROVEURL} ${approvalRequest.APPROVALCOMMENT} ${requestAdmin.USERNAME} ${approvalAdmin.USERNAME} ${approvalAdmin.CN}");
        assertEquals("123 testaproval user Org 2 http://approval.test/ Comment username approvalUsername approvaluser", msg);
		
	}
	

}
