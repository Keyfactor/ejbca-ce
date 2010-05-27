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
package org.ejbca.ui.web.protocol;

/**
 * @version $Id$
 */
public interface IHealtChecker {

	/**
     * To be called by healthcheck servlet.
     * 
     * @param doSignTest true if the a sign test should be done with the key.
     * @param doValidityTest true if the validity of the signing certificates should be checked
	 * @return health check answer. "" means everything OK.
	 */
	String healthCheck(boolean doSignTest, boolean doValidityTest);

}
