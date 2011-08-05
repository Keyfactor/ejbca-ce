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

import org.cesecore.CesecoreException;




/**
 * Error due to malformed key. The cause of failure can be related to illegal key length etc.
 *
 * Based on EJBCA version: IllegalKeyException.java 10392 2010-11-08 08:22:39Z mikekushner
 * 
 * @version $Id: IllegalKeyException.java 451 2011-03-07 07:56:04Z tomas $
 */
public class IllegalKeyException extends CesecoreException {

    private static final long serialVersionUID = -3144774253953346584L;
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
