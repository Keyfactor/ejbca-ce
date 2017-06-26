/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.profiles;

import org.cesecore.CesecoreException;


/**
 * An exception thrown when someone tries to change an profile that doesn't already exits
 * 
 * @version $Id$
 */
public class ProfileDoesNotExistException extends CesecoreException {
    

    private static final long serialVersionUID = -1038676703612812109L;


    /**
     * Creates a new instance of <code>ProfileDoesNotExistException</code> without detail message.
     */
    public ProfileDoesNotExistException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>ProfileDoesNotExistException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ProfileDoesNotExistException(String msg) {
        super(msg);
    }
}
