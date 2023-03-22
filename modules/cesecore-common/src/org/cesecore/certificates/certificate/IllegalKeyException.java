/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate;

import com.keyfactor.CesecoreException;

/**
 * Error due to malformed key. The cause of failure can be related to illegal key length etc.
 *
 * @version $Id$
 */
public class IllegalKeyException extends CesecoreException {

    private static final long serialVersionUID = -3144774253953346584L;
    
    public IllegalKeyException(String message, Throwable cause) {
        super(message, cause);
    }
   
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public IllegalKeyException(String message) {
        super(message);
    }
    /**
     * Constructs an instance of <code>IllegalKeyException</code> with the specified cause.
     * @param msg the detail message.
     */
    public IllegalKeyException(Exception e) {
        super(e);
    }
}
