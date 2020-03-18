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

package org.ejbca.core.protocol;

import org.cesecore.certificates.certificate.request.RequestMessage;


/**
 * To be implemented by classes that is extending the handling of the user data.
 * Could be to store it or to change something in DN.
 * 
 * @version $Id$
 */
public interface ExtendedUserDataHandler {
	/**
	 * Called when the data handling should be done.
	 * @param req Request to be modified.
	 * @param otherData some other data
	 * @return the modified request
	 */
	RequestMessage processRequestMessage(RequestMessage req, String otherData);

}
