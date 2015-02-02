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
 * Thrown when the PKCS11 slot property value is invalid
 * @version $Id$
 *
 */
@WebFault
public class PKCS11SlotDataInvalidException extends EjbcaException {




    private static final long serialVersionUID = 7197787941794988403L;

    /**
     * @param message with more information what is wrong
     */
    public PKCS11SlotDataInvalidException(String m) {
        super(ErrorCode.PKCS11_SLOT_DATA_INVALID, m);
    }
}
