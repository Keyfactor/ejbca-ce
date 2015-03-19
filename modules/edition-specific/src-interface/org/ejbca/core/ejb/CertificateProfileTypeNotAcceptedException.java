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
package org.ejbca.core.ejb;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * Thrown when trying to use a certificate or end entity profile of the wrong type
 * @version $Id$
 *
 */
public class CertificateProfileTypeNotAcceptedException extends EjbcaException {

    private static final long serialVersionUID = 1L;

    /**
     * @param message with more information what is wrong
     */
    public CertificateProfileTypeNotAcceptedException(String m) {
        super(ErrorCode.BAD_CERTIFICATE_PROFILE_TYPE, m);
    }
}
