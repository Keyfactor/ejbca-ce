/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.audit.audit;

import org.cesecore.audit.log.AuditLogResetException;
import org.junit.Assert;
import org.junit.Test;

/**
 * Test of LogServiceState.  
 * 
 * @version $Id$
 */
public class LogServiceStateTest {

	private static final String MSG_NOT_DISABLED = "LogServiceState was not disabled as expected.";
	private static final String MSG_NOT_ENABLED = "LogServiceState was not enabled as expected.";
	private static final String MSG_SAME_TWICE = "No Exception when state was set to the same twice.";

	@Test
	public void testStateChanges() throws AuditLogResetException {
		// We want to run this test twice to toggle it back and forth..
	    stateChangesInternalTest();
	    stateChangesInternalTest();
	}

	public void stateChangesInternalTest() throws AuditLogResetException {
		// Since it is a singleton, we go with the state it happens to be in.
		final boolean originalStateDisabled = LogServiceState.INSTANCE.isDisabled();
		// Toggle the state once and verify that it changed.
		if (originalStateDisabled) {
			LogServiceState.INSTANCE.enable();
			Assert.assertFalse(MSG_NOT_ENABLED, LogServiceState.INSTANCE.isDisabled());
		} else {
			LogServiceState.INSTANCE.disable();
			Assert.assertTrue(MSG_NOT_DISABLED, LogServiceState.INSTANCE.isDisabled());
		}
		// Toggle the state a second time, verify that this results in a Exception and that the state is the same.
		if (originalStateDisabled) {
			try {
				LogServiceState.INSTANCE.enable();
				Assert.fail(MSG_SAME_TWICE);
			} catch (AuditLogResetException e) {
				Assert.assertFalse(MSG_NOT_ENABLED, LogServiceState.INSTANCE.isDisabled());
			}
		} else {
			try {
				LogServiceState.INSTANCE.disable();
				Assert.fail(MSG_SAME_TWICE);
			} catch (AuditLogResetException e) {
				Assert.assertTrue(MSG_NOT_DISABLED, LogServiceState.INSTANCE.isDisabled());
			}
		}
	}
}
