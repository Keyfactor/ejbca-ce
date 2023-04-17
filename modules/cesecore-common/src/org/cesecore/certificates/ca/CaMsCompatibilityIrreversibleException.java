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

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;


/**
 * An exception thrown when someone tries to change Microsoft Compatibility from true to false.
 */
public class CaMsCompatibilityIrreversibleException extends CesecoreException {

    private static final long serialVersionUID = 4963339387893829787L;

    /**
     * Creates a new instance without detail message.
     */
    public CaMsCompatibilityIrreversibleException() {
        super(ErrorCode.CA_MS_COMPATIBILITY_IRREVERSIBLE);
    }

    /**
     * Constructs an instance of with the specified detail message.
     * @param msg the detail message.
     */
    public CaMsCompatibilityIrreversibleException(String msg) {
        super(ErrorCode.CA_MS_COMPATIBILITY_IRREVERSIBLE, msg);
    }

    /**
     * Constructs an instance with the specified cause.
     * @param e the Exception has details about the cause.
     */
    public CaMsCompatibilityIrreversibleException(Exception e) {
        super(e);
    }
}
