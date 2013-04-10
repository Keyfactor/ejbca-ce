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
package org.ejbca.core.ejb.signer;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * An exception thrown when someone tries to create a SignerMapping with an existing name.
 *
 * @version $Id$
 */
public class SignerMappingNameInUseException extends EjbcaException {

    private static final long serialVersionUID = 1L;
    private static final String _SIGNER_MAPPING_NAME_IN_USE = "SIGNER_MAPPING_NAME_IN_USE";
    public static final ErrorCode SIGNER_MAPPING_NAME_IN_USE = ErrorCode.NOT_SPECIFIED;
    {
        // Work-around for a not so convenient API
        SIGNER_MAPPING_NAME_IN_USE.setInternalErrorCode(_SIGNER_MAPPING_NAME_IN_USE);
    }

    /**
     * Creates a new instance of <code>SignerNameInUseException</code> without detail message.
     */
    public SignerMappingNameInUseException() {
        super(SIGNER_MAPPING_NAME_IN_USE);
    }

    /**
     * Constructs an instance of <code>SignerNameInUseException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public SignerMappingNameInUseException(String msg) {
        super(SIGNER_MAPPING_NAME_IN_USE, msg);
    }

    /**
     * Constructs an instance of <code>SignerNameInUseException</code> with the specified detail message.
     * @param exception the exception that caused this
     */
    public SignerMappingNameInUseException(Exception exception) {
        super(SIGNER_MAPPING_NAME_IN_USE, exception);
    }

    /**
     * Constructs an instance of <code>SignerNameInUseException</code> with the specified detail message.
     * @param msg the detail message.
     * @param exception the exception that caused this
     */
    public SignerMappingNameInUseException(String msg, Exception e) {
        super(SIGNER_MAPPING_NAME_IN_USE, msg, e);
    }
}
