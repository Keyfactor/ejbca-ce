package org.ejbca.core.model.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

/** Tests some substitution variables for approval profile notifications
 * @version $Id$
 */
public class ApprovalNotificationParamGenTest {

	@Test
	public void testInterpolate(){
        final ApprovalNotificationParameterGenerator paramGen = new ApprovalNotificationParameterGenerator(123, 3, 47,
                "Approval Step $1", ApprovalDataVO.APPROVALTYPENAMES[0], "approved", "CN=requestor\\me", "CN=Last approved by");
        assertNotNull("paramGen is null", paramGen);
        
        String msg = paramGen.interpolate("${approvalRequest.ID} ${approvalRequest.STEP_ID} ${approvalRequest.PARTITION_ID} ${approvalRequest.PARTITION_NAME} ${approvalRequest.TYPE} ${approvalRequest.WORKFLOWSTATE} ${approvalRequest.REQUESTOR} ${approvalRequest.APPROVALADMIN}");
        assertFalse("Interpolating message failed", (msg==null || msg.length()==0));
        assertEquals("123 3 47 Approval Step $1 APDUMMY approved CN=requestor\\me CN=Last approved by", msg);
		
	}
	

}
