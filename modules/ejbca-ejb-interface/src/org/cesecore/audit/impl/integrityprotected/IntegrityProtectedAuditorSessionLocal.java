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

import java.util.Date;
import java.util.Properties;

import javax.ejb.Local;

import org.cesecore.audit.Auditable;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Allows auditing of securely logged events.
 * 
 * See {@link https
 * ://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_
 * (ADV_FSP)#Audit_Security_Events}
 * 
 * @version $Id$
 */
@Local
public interface IntegrityProtectedAuditorSessionLocal extends Auditable {

	/**
	 * Delete all log entries up to the specified time
	 * @return number of rows deleted
	 * @throws AuthorizationDeniedException unless token has StandardRules.AUDITLOGEXPORT rights
	 */
	int deleteRows(AuthenticationToken token, Date timestamp, Properties properties) throws AuthorizationDeniedException;
}
