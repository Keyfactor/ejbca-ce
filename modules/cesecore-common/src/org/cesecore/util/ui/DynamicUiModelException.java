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
package org.cesecore.util.ui;

/**
 * Any exception in dynamic UI property context.
 * 
 * @version $Id: DynamicUiPropertyException.java 24964 2017-12-23 08:15:35Z anjakobs $
 *
 */
public class DynamicUiModelException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message and a cause.
     * 
     * @param message the message.
     * @param cause the cause.
     */
    public DynamicUiModelException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates an exception with a message.
     * @param message the message.
     */
    public DynamicUiModelException(final String message) {
        super(message);
    }

    /**
     * Creates an exception a cause.
     * @param cause the cause.
     */
    public DynamicUiModelException(final Throwable cause) {
        super(cause);
    }
}
