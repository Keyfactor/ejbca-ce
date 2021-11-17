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
package org.ejbca.core.ejb.approval;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Dummy CA Approval Request used for testing purpose.
 */
public class DummyCaApprovalRequest extends DummyApprovalRequest {

	private static final long serialVersionUID = -2L;

	public DummyCaApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int cAId, int endEntityProfileId,
								boolean executable, final ApprovalProfile approvalProfile) {
		super(requestAdmin, requestSignature, cAId, endEntityProfileId, executable, approvalProfile);
	}

	/** Constructor used in externalization only */
	public DummyCaApprovalRequest() {
	}

	@Override
    public int getApprovalType(){
		return ApprovalDataVO.APPROVALTYPE_ACTIVATECATOKEN;
	}
}
