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
package org.cesecore.audit.impl.integrityprotected;

import javax.ejb.Local;

import org.cesecore.audit.AuditLogger;

/**
 * Based on CESeCore version:
 *      IntegrityProtectedLoggerSessionLocal.java 907 2011-06-22 14:42:15Z johane
 * 
 * @version $Id$
 */
@Local
public interface IntegrityProtectedLoggerSessionLocal extends AuditLogger {
}
