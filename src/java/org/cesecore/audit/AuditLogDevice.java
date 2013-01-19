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
package org.cesecore.audit;

import java.util.Map;

import org.cesecore.audit.log.AuditLogResetException;

/**
 * Interface for Secure Audit Log device that can be logged to or read from.
 * 
 * @version $Id$
 */
public interface AuditLogDevice extends Auditable, AuditLogger {

	/** Setter for the ejbs that the log devices can invoke.. */
	void setEjbs(Map<Class<?>, ?> ejbs);
	
	/** @return true if this device can respond to queries. */
	boolean isSupportingQueries();
	
    /**
     * Prepares the secure audit log mechanism for reset.
     * This method will block till all audit log processes are completed. 
     * Should be used with caution because once called audit log will not be operational. 
     * Any attempt to log will result in an exception.
     */
    void prepareReset() throws AuditLogResetException;

    /**
     * Resets all security audit events logger internal state.
     * Once this method finishes the audit log will be available again.
     * This method should be used with caution.
     */
    void reset() throws AuditLogResetException;
}
