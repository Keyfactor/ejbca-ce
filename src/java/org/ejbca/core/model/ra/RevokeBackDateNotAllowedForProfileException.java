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

package org.ejbca.core.model.ra;

import javax.xml.ws.WebFault;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * The certificate profile is not allowing revocation back date.
 * @version $Id$
 *
 */
@WebFault
public class RevokeBackDateNotAllowedForProfileException extends EjbcaException {

	private static final long serialVersionUID = -707975049447839896L;

	public RevokeBackDateNotAllowedForProfileException(String m) {
		super(ErrorCode.REVOKE_BACKDATE_NOT_ALLOWED, m);
	}
}
