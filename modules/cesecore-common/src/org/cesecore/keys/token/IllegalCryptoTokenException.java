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
 * Error due to malformed key store. The cause of failure can be related to illegal key length etc.
 *
 * @version $Id$
 */
public class IllegalCryptoTokenException extends CesecoreException {
   
    private static final long serialVersionUID = 7059969615144222041L;
  
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public IllegalCryptoTokenException(String message) {
        super(message);
    }
    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public IllegalCryptoTokenException(Exception exception) {
        super(exception);
    }
}
