/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.log;

/**
 * Sloppy Singleton used to hold results of ProtectedLogTestAction.
 */
public class ProtectedLogTestActionResult {
	
	private static ProtectedLogTestActionResult instance = null;
	private String cause = null;
	
	private ProtectedLogTestActionResult() {}
	
	public static synchronized ProtectedLogTestActionResult getInstance() {
		if (instance == null) {
			instance = new ProtectedLogTestActionResult();
		}
		return instance;
	}
	
	public String getCause() { return cause; }
	public void setCause(String cause) { this.cause = cause; }
}
