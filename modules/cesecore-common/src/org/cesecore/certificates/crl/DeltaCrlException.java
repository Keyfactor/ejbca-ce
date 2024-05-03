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
 
 
package org.cesecore.certificates.crl;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

public class DeltaCrlException extends CesecoreException {

    private static final long serialVersionUID = -7135950339338046417L;

    /**
     * Creates a new instance without detail message.
     */
    public DeltaCrlException() {
        super(ErrorCode.DELTA_CRL_NOT_AVAILABLE);
    }

    /**
     * Constructs an instance of with the specified detail message.
     * @param msg the detail message.
     */
    public DeltaCrlException(String msg) {
        super(ErrorCode.DELTA_CRL_NOT_AVAILABLE, msg);
    }

    /**
     * Constructs an instance of with the specified cause.
     * @param e exception.
     */
    public DeltaCrlException(Exception e) {
        super(e);
    }
}
