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
 * Any exception in dynamic UI property context which transports a user message. 
 * There is no inner exception, only the message MUST BE used.
 * 
 * @version $Id: DynamicUiCallbackException.java 27100 2018-01-03 10:15:35Z anjakobs $
 *
 */
public final class DynamicUiCallbackException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message.
     * @param message the message.
     */
    public DynamicUiCallbackException(final String message) {
        super(message);
    }

    @SuppressWarnings("unused")
    private DynamicUiCallbackException(final Throwable throwable) {
        super(throwable);
    }

    @SuppressWarnings("unused")
    private DynamicUiCallbackException(final String message, final Throwable throwable) {
        super(message, throwable);
    }
}
