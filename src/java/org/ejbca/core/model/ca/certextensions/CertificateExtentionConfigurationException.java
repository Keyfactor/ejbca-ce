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

package org.ejbca.core.model.ca.certextensions;

/**
 * Execption thrown of advanced certificate extensions
 * when it is configured with bad propeties.
 * 
 * 
 * @author Philip Vendil 2007 jan 5
 *
 * @version $Id$
 */

public class CertificateExtentionConfigurationException extends Exception {

	/**
	 * Execption thrown of advanced certificate extensions
     * when it is configured with bad propeties.
	 */
	public CertificateExtentionConfigurationException(String message, Throwable throwable) {
		super(message, throwable);
	}

	/**
	 * Execption thrown of advanced certificate extensions
     * when it is configured with bad propeties.
	 */
	public CertificateExtentionConfigurationException(String message) {
		super(message);
	}

}
