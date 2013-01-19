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

import javax.ejb.Local;

import org.cesecore.audit.log.AuditLogResetException;

/**
 * Local interface for the SecurityEventsAuditor
 * 
 * @see SecurityEventsAuditorSession
 * 
 * @version $Id$
 */
@Local
public interface SecurityEventsAuditorSessionLocal extends SecurityEventsAuditorSession {

    /** @see org.cesecore.audit.AuditLogDevice#prepareReset() */
    void prepareReset() throws AuditLogResetException;

    /** @see org.cesecore.audit.AuditLogDevice#reset() */
    void reset() throws AuditLogResetException;
}
