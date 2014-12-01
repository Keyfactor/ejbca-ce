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
 * Thrown when the profile type is neither an end entity profile nor a certificate profile
 * @version $Id$
 *
 */
@WebFault
public class UnknownProfileTypeException extends EjbcaException {



    private static final long serialVersionUID = 1L;

    /**
     * @param message with more information what is wrong
     */
    public UnknownProfileTypeException(String m) {
        super(ErrorCode.UNKNOWN_PROFILE_TYPE, m);
    }
}
