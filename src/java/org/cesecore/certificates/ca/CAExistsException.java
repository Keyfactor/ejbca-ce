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


/**
 * An exception thrown when someone tries to change or create a CA that doesn't already exits
 *
 * Based on EJBCA version: CAExistsException.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id$
 */
public class CAExistsException extends CesecoreException {
    
    private static final long serialVersionUID = 1212559890080635864L;


    /**
     * Creates a new instance of <code>CAExistsException</code> without detail message.
     */
    public CAExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CAExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CAExistsException(String msg) {
        super(msg);
    }
}
