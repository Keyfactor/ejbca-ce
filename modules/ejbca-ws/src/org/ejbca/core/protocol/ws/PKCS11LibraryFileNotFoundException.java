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

package org.ejbca.core.protocol.ws;

import javax.xml.ws.WebFault;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * Thrown when the no PKCS11 library file is specified or when the specified PKCS11 library 
 * file is not found
 * @version $Id$
 *
 */
@WebFault
public class PKCS11LibraryFileNotFoundException extends EjbcaException {



    private static final long serialVersionUID = 1639115377050156144L;

    /**
     * @param message with more information what is wrong
     */
    public PKCS11LibraryFileNotFoundException(String m) {
        super(ErrorCode.PKCS11_LIBRARY_NOT_FOUND, m);
    }
}
