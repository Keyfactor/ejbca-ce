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

import java.util.Date;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.util.NotificationParamGen;

/**
 * Variables that can be parsed for approvals.
 * 
 * ${approvalRequest.DATE}            = The time the approval request was created
 * ${approvalRequest.ID}              = The id of the approval request
 * ${approvalRequest.ABS.ID}          = The id of the approval request with out any '-' sign, used for presentation purposes.
 * ${approvalRequest.TYPE}            = The type of approval request
 * ${approvalRequest.APROVEURL}       = A URL to the review approval page with the current request.
 * ${approvalRequest.APPROVALSLEFT}   = The number of approvals remaining.
 * ${approvalRequest.APPROVALCOMMENT} = The comment made by the approving/rejecting administrator
 * 
 * ${requestAdmin.USERNAME}           = The requesting administrator's username
 * ${requestAdmin.CN}                 = The common name of the requesting administrator.
 * ${requestAdmin.SN}                 = The common name of the requesting administrator.
 * ${requestAdmin.O}                  = The requesting administrator's organization
 * ${requestAdmin.OU}                 = The requesting administrator's organization unit
 * ${requestAdmin.C}                  = The requesting administrator's country 
 * 
 * ${approvalAdmin.USERNAME}          = The approving administrator's username
 * ${approvalAdmin.CN}                = The common name of the approving administrator.
 * ${approvalAdmin.SN}                = The common name of the approving administrator.
 * ${approvalAdmin.O}                 = The approving administrator's organization
 * ${approvalAdmin.OU}                = The approving administrator's organization unit
 * ${approvalAdmin.C}                 = The approving administrator's country
 * 
 * @version $Id$
 */
public class ApprovalNotificationParamGen extends NotificationParamGen {

	protected ApprovalNotificationParamGen() { }

	/**
	 * Constructor that mainly should be used when generating approval notifications 
	 */
	public ApprovalNotificationParamGen(Date approvalRequestDate, Integer approvalRequestID, String approvalRequestType,
			Integer numberOfApprovalLeft, String approvalRequestURL, String approveComment, String requestAdminUsername, String requestAdminDN,
			String approvalAdminUsername, String approvalAdminDN) {
		if (approvalRequestDate != null) {
			String requestDate = fastDateFormat(approvalRequestDate);
			paramPut("approvalRequest.DATE", requestDate);	      
		} else {
			paramPut("approvalRequest.DATE", "");	
		}
		paramPut("approvalRequest.ID", approvalRequestID);
		if (approvalRequestID != null) {
			paramPut("approvalRequest.ABS.ID", Integer.valueOf(Math.abs(approvalRequestID.intValue())));
		}
		paramPut("approvalRequest.TYPE", approvalRequestType);
		// Wrong spelled parameter kept for backwards compatibility
		paramPut("approvalReqiest.APPROVALSLEFT", numberOfApprovalLeft);	      	  	  	  		  
		paramPut("approvalRequest.APPROVALSLEFT", numberOfApprovalLeft);	      	  	  	  		  
		paramPut("approvalRequest.APROVEURL", approvalRequestURL);	      
		paramPut("approvalRequest.APPROVALCOMMENT", approveComment);	      
		paramPut("requestAdmin.USERNAME", requestAdminUsername);	  

		if (requestAdminDN == null) {
			requestAdminDN = "";
		}
		DNFieldExtractor dnfields = new DNFieldExtractor(requestAdminDN, DNFieldExtractor.TYPE_SUBJECTDN);	      
		paramPut("requestAdmin.CN", dnfields.getField(DNFieldExtractor.CN, 0));	      
		paramPut("requestAdmin.SN", dnfields.getField(DNFieldExtractor.SN, 0));
		paramPut("requestAdmin.O", dnfields.getField(DNFieldExtractor.O, 0));
		paramPut("requestAdmin.OU", dnfields.getField(DNFieldExtractor.OU, 0));
		paramPut("requestAdmin.C", dnfields.getField(DNFieldExtractor.C, 0));
		paramPut("requestAdmin.E", dnfields.getField(DNFieldExtractor.E, 0));

		paramPut("approvalAdmin.USERNAME", approvalAdminUsername);

		populateWithApprovalAdminDN(approvalAdminDN);
	}

	protected void populateWithApprovalAdminDN(String approvalAdminDN) {
		if (approvalAdminDN == null) {
			approvalAdminDN = "";
		}
		DNFieldExtractor dnfields = new DNFieldExtractor(approvalAdminDN, DNFieldExtractor.TYPE_SUBJECTDN);	      
		paramPut("approvalAdmin.CN", dnfields.getField(DNFieldExtractor.CN, 0));	      
		paramPut("approvalAdmin.SN", dnfields.getField(DNFieldExtractor.SN, 0));
		paramPut("approvalAdmin.O", dnfields.getField(DNFieldExtractor.O, 0));
		paramPut("approvalAdmin.OU", dnfields.getField(DNFieldExtractor.OU, 0));
		paramPut("approvalAdmin.C", dnfields.getField(DNFieldExtractor.C, 0));
		paramPut("approvalAdmin.E", dnfields.getField(DNFieldExtractor.E, 0));
	}
}
