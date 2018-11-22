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

import javax.xml.ws.WebFault;

import org.cesecore.NonSensitiveException;

/**
 * Exception thrown from actions that stop to wait for approvals.
 * <p>
 * This exception contains the requestId of the approval request,
 * which can be used together with {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#getRemainingNumberOfApprovals IEjbcaWS.getRemainingNumberOfApprovals}
 * to check the status.
 * 
 * @version $Id$
 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getRemainingNumberOfApprovals IEjbcaWS.getRemainingNumberOfApprovals
 */
@WebFault
@NonSensitiveException
public class WaitingForApprovalException extends Exception {

	private static final long serialVersionUID = 6808192333114783496L;
    private int requestId = 0;
	
	public WaitingForApprovalException(String message, int requestId) {
		super(message);
		this.requestId = requestId;
	}
	
	/**
	 * The requestId of the approval request. It can be used together with
	 * {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#getRemainingNumberOfApprovals IEjbcaWS.getRemainingNumberOfApprovals}
	 * to check the status.
	 */
	public int getRequestId(){
		return requestId;
	}

}
