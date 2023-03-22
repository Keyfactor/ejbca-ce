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

import javax.xml.ws.WebFault;

import com.keyfactor.CesecoreException;


/**
 * Error due to malformed certificate request. The cause of failure can be related to ASN.1,
 * algorithm or other
 * 
 * Probably based on EJBCA's org.ejbca.core.model.ca.SignRequestException r11201
 */
@WebFault
public class SignRequestException extends CesecoreException {
  
    private static final long serialVersionUID = 4368820010501466071L;

    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public SignRequestException(String message) {
        super(message);
    }
}
