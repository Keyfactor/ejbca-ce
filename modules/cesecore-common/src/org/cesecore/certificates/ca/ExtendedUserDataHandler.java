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

package org.cesecore.certificates.ca;

import java.io.Serializable;

import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;


/**
 * To be implemented by classes that is extending the handling of the user data.
 * Could be to store it or to change something in DN.
 * 
 */
public interface ExtendedUserDataHandler extends Serializable {
	/**
	 * Called when the data handling should be done.
	 * @param req Request to be modified.
	 * @param certificateProfileName the name of the certificate profile
	 * @return the modified request
	 */
	RequestMessage processRequestMessage(final RequestMessage req, final String certificateProfileName);
	
	/**
	 * Produces the same manipulation as processRequestMessage, but directly on an EndEntityInformation object. 
	 * 
	 * @param endEntityInformation to be modified.
	 * @param certificateProfileName the name of the certificate profile
	 * @return a safe copy of the EndEntityInformation object
	 */
	EndEntityInformation processEndEntityInformation(final EndEntityInformation endEntityInformation, final String certificateProfileName);
	
	/**
	 * 
	 * @return a human readable name for this implementation
	 */
	String getReadableName();

}
