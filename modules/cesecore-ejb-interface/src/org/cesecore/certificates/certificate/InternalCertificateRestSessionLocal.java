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
package org.cesecore.certificates.certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

import javax.ejb.Local;

/**
 * The local bean which holds only internal functionality needed for the CA performance.
 * As an example the count of the total or active certificates etc.
 */
@Local
public interface InternalCertificateRestSessionLocal {

	/**
	 * Returns the number of total or active certificates.
	 *
	 * @param adminToken an admin authentication token.
	 * @param isActive if true then returns the number of active certificates only.
	 * @return certificate quantity.
	 */
	Long getCertificateCount(AuthenticationToken adminToken, Boolean isActive) throws AuthorizationDeniedException;
}
