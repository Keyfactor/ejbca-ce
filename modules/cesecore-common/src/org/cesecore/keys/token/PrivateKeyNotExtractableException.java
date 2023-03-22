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
package org.cesecore.keys.token;

import com.keyfactor.CesecoreException;

/**
 * An exception thrown when someone tries to extract a Private Key from a Crypto Token that doesn't allow it.
 *
 * @version $Id$
 */
public class PrivateKeyNotExtractableException extends CesecoreException {

    private static final long serialVersionUID = -5484077868101864920L;

    
    /**
     * Creates a new instance of <code>PrivateKeyNotExtractableException</code> with the cause 
     */
    public PrivateKeyNotExtractableException(Exception exception) {
        super(exception);       
    }

    
    /**
     * Creates a new instance of <code>PrivateKeyNotExtractableException</code> with the specified detail message and cause 
     */
    public PrivateKeyNotExtractableException(String message, Throwable cause) {
        super(message, cause);
    }

    
    /**
     * Creates a new instance of <code>PrivateKeyNotExtractableException</code> with the specified detail message 
     */
    public PrivateKeyNotExtractableException(String message) {
        super(message);
    }

    
}
