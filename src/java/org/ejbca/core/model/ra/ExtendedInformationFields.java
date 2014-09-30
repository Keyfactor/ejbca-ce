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

/**
 * Constants specific to EJBCA that are used to store EJBCA specific extended information
 *  
 * @version $Id$
 */
public class ExtendedInformationFields {

    /**
     * Identifier for Custom data holding a base64 encoded PKCS10 request extInfo.setCustomData("PKCS10", new
     * String(Base64.encode(pkcs10.getEncoded())));
     * Not used internally by CESeCore but useful for applications.
     */
    public  static final String CUSTOM_PKCS10 = "PKCS10";
    
	/** The (optional) counter is the counter how many request have been received, will decrease for every request until 0. */
	public  static final String CUSTOM_REQUESTCOUNTER = "REQUESTCOUNTER";

}
