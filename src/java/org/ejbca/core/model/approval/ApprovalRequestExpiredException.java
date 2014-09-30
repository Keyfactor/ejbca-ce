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

/**
 * Exception throws after approving,executing or requesting actions
 * that have expired in the approval database
 * 
 * @author Philip Vendil
 * @version $Id$
 */
@WebFault
public class ApprovalRequestExpiredException extends Exception {

	private static final long serialVersionUID = 170838528150319772L;

    public ApprovalRequestExpiredException() {
		super();
	}

	public ApprovalRequestExpiredException(String message) {
		super(message);
	}

}
