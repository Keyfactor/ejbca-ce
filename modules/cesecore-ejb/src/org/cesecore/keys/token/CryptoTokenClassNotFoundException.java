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
package org.cesecore.keys.token;

/**
 * Thrown when trying to instantiate an unknown crypto token class.
 * 
 * @version $Id$
 *
 */
public class CryptoTokenClassNotFoundException extends RuntimeException {

    private static final long serialVersionUID = -7935523503522491237L;
    
    public CryptoTokenClassNotFoundException() {
        super();
    }

    public CryptoTokenClassNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoTokenClassNotFoundException(String message) {
        super(message);
    }

    public CryptoTokenClassNotFoundException(Throwable cause) {
        super(cause);
    }

  

}
