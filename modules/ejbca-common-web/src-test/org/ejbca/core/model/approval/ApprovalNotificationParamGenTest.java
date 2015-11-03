package org.ejbca.core.model.approval;

import static org.junit.Assert.assertEquals;

import java.util.Date;

import org.junit.Test;

/** Tests some substitution variables for approval notifications
 * 
 * @version $Id$
 */
public class ApprovalNotificationParamGenTest {

    @Test
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
