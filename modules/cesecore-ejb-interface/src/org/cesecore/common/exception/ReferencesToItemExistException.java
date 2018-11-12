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
package org.cesecore.common.exception;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * Thrown when trying to delete an item when references to it exist.
 * For example when trying to delete a Publisher when it is used in Certificate Profiles.
 * <p>
 * The message contains details about which objects or which types of objects contain the references.
 * @version $Id$
 */
public class ReferencesToItemExistException extends CesecoreException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new instance of <code>ReferencesToItemExistException</code> without detail message.
     * @deprecated A message describing which types of objects are referencing the item should be included. This constructor is for deserialization only.
     */
    @Deprecated
    public ReferencesToItemExistException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>ReferencesToItemExistException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ReferencesToItemExistException(String msg) {
        super(ErrorCode.REFERENCES_TO_ITEM_EXIST, msg);
    }

    /**
     * Constructs an instance of <code>ReferencesToItemExistException</code> with the specified detail message and cause.
     * @param msg the detail message.
     * @param cause exception causing this exception.
     */
    public ReferencesToItemExistException(String message, Throwable cause) {
        super(message, cause);
    }
}
