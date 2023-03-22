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
package org.cesecore.keybind;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

/**
 * An exception thrown when someone tries to create an InternalKeyBinding with a nonce setting that conflicts with the CA's OCSP response pre-production setting.
 *
 * @version $Id$
 */
public class InternalKeyBindingNonceConflictException extends CesecoreException {

    private static final long serialVersionUID = 1L;
    public static final ErrorCode INTERNAL_KEY_BINDING_NONCE_CONFLICT = ErrorCode.INTERNAL_KEY_BINDING_NONCE_CONFLICT;

    /**
     * Creates a new instance of <code>InternalKeyBindingNonceConflictException</code> without detail message.
     */
    public InternalKeyBindingNonceConflictException() {
        super(INTERNAL_KEY_BINDING_NONCE_CONFLICT);
    }

    /**
     * Constructs an instance of <code>InternalKeyBindingNonceConflictException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public InternalKeyBindingNonceConflictException(String msg) {
        super(INTERNAL_KEY_BINDING_NONCE_CONFLICT, msg);
    }

    /**
     * Constructs an instance of <code>InternalKeyBindingNonceConflictException</code> with the specified detail message.
     * @param exception the exception that caused this
     */
    public InternalKeyBindingNonceConflictException(Exception exception) {
        super(INTERNAL_KEY_BINDING_NONCE_CONFLICT, exception);
    }

    /**
     * Constructs an instance of <code>InternalKeyBindingNonceConflictException</code> with the specified detail message.
     * @param msg the detail message.
     * @param exception the exception that caused this
     */
    public InternalKeyBindingNonceConflictException(String msg, Exception e) {
        super(INTERNAL_KEY_BINDING_NONCE_CONFLICT, msg, e);
    }
}
