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

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;


/**
 * Thrown when trying to create a new CA signed by an external CA using the WS *
 * @version $Id$
 */
public class SignedByExternalCANotSupportedException extends CesecoreException {

    
    private static final long serialVersionUID = -8917528643510939912L;

    /**
     * Constructs an instance of <code>SignedByExternalCANotSupportedException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public SignedByExternalCANotSupportedException(String msg) {
        super(ErrorCode.SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED, msg);
    }
    
}
