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

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;
import org.junit.Test;

/**
 * @version $Id$
 */
public class ApprovalExceptionTest {

	/**
	 * Verify that nested ApprovalExceptions propagate errorCode.
	 */
	@Test
	public void testErrorCode() {
		ApprovalException approvalException = new ApprovalException(ErrorCode.APPROVAL_ALREADY_EXISTS, "JUnit test message..");
		EjbcaException ejbcaException = new EjbcaException(approvalException);
		assertEquals("EjbcaException did not inherit ErrorCode.", ErrorCode.APPROVAL_ALREADY_EXISTS, ejbcaException.getErrorCode());
	}
}
