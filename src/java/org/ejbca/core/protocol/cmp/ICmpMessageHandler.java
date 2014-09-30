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

package org.ejbca.core.protocol.cmp;

import org.cesecore.certificates.certificate.request.ResponseMessage;

/**
 * Interface for message handler handling a specific CMP message
 * @author tomas
 * @version $Id$
 */
public interface ICmpMessageHandler {
	
	/**
	 * 
	 * @param msg input message
	 * @param authenticated if the CMP message has already been authenticated
	 * @return response message
	 */
	public ResponseMessage handleMessage(BaseCmpMessage msg, boolean authenticated);

}
